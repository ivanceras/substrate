// Copyright 2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! rpc api for babe.

use std::{fmt, io};
use futures::{
	FutureExt as _, TryFutureExt as _,
	executor::ThreadPool,
	channel::oneshot,
	future::ready,
};
use sp_consensus_babe::{AuthorityId, Epoch, BabePreDigest};
use crate::{SharedEpochChanges, authorship, epoch_changes::descendent_query, Config};
use sc_keystore::KeyStorePtr;
use std::sync::Arc;
use sp_core::crypto::Pair;
use sp_runtime::traits::{Block as BlockT, Header as _};
use sp_consensus::{SelectChain, Error as ConsensusError};
use sp_consensus_babe::BabeApi;
use sp_blockchain::{HeaderBackend, HeaderMetadata, Error as BlockChainError};
use serde::{Deserialize, Serialize};
use sp_api::{ProvideRuntimeApi, BlockId};
use std::collections::HashMap;
use jsonrpc_core::{
	Error as RpcError,
	futures::future as rpc_future,
};
use jsonrpc_derive::rpc;

type FutureResult<T> = Box<dyn rpc_future::Future<Item = T, Error = RpcError> + Send>;

pub use self::rpc_impl_Babe::gen_server;
/// Provides rpc methods for interacting with Babe
#[rpc]
pub trait Babe {
	/// query slot authorship info
	#[rpc(name = "babe_epochAuthorship")]
	fn epoch_authorship(&self) -> FutureResult<HashMap<AuthorityId, SlotAuthorship>>;
}

/// RPC handler for Babe
/// provides `babe_epochAuthorship` method for querying slot authorship data.
///
/// Uses a background thread to calculate epoch_authorship data.
pub struct BabeRPC<B: BlockT, C, SC> {
	/// shared refernce to the client.
	client: Arc<C>,
	/// shared reference to EpochChanges
	shared_epoch_changes: SharedEpochChanges<B>,
	/// shared reference to the Keystore
	keystore: KeyStorePtr,
	/// config (actually holds the slot duration)
	babe_config: Config,
	/// threadpool for spwaning cpu bound tasks.
	threadpool: ThreadPool,
	/// select chain
	select_chain: Arc<SC>,
}

impl<B: BlockT, C, SC> BabeRPC<B, C, SC> {
	/// creates a new instance of the BabeRpc handler.
	pub fn new(
		client: Arc<C>,
		shared_epoch_changes: SharedEpochChanges<B>,
		keystore: KeyStorePtr,
		babe_config: Config,
		select_chain: Arc<SC>,
	) -> io::Result<Self> {
		let threadpool = ThreadPool::builder()
			// single thread is fine.
			.pool_size(1)
			.create()?;

		Ok(Self {
			client,
			shared_epoch_changes,
			keystore,
			babe_config,
			threadpool,
			select_chain,
		})
	}
}

impl<B, C, SC> Babe for BabeRPC<B, C, SC>
	where
		B: BlockT,
		C: ProvideRuntimeApi<B> + HeaderBackend<B>
		+ HeaderMetadata<B, Error=BlockChainError> + 'static,
		C::Api: BabeApi<B>,
		<<C as ProvideRuntimeApi<B>>::Api as sp_api::ApiErrorExt>::Error: fmt::Debug,
		SC: SelectChain<B> + 'static,
{
	fn epoch_authorship(&self) -> FutureResult<HashMap<AuthorityId, SlotAuthorship>> {
		let (
			babe_config,
			keystore,
			shared_epoch,
			client,
			select_chain,
		) = (
			self.babe_config.clone(),
			self.keystore.clone(),
			self.shared_epoch_changes.clone(),
			self.client.clone(),
			self.select_chain.clone(),
		);
		let (tx, rx) = oneshot::channel();

		let future = async move {
			let header = select_chain.best_chain().map_err(Error::Consensus)?;
			let epoch_start = client.runtime_api()
				.current_epoch_start(&BlockId::Hash(header.hash()))
				.map_err(|err| {
					Error::StringError(format!("{:?}", err))
				})?;
			let epoch = epoch_data(&shared_epoch, &client, &babe_config, epoch_start, &select_chain)?;
			let (epoch_start, epoch_end) = (epoch.start_slot, epoch.end_slot());

			let mut claims: HashMap<AuthorityId, SlotAuthorship> = HashMap::new();

			for slot_number in epoch_start..=epoch_end {
				let epoch = epoch_data(&shared_epoch, &client, &babe_config, slot_number, &select_chain)?;
				let slot = authorship::claim_slot(slot_number, &epoch, &babe_config, &keystore);
				if let Some((claim, key)) = slot {
					match claim {
						BabePreDigest::Primary { .. } => {
							claims.entry(key.public()).or_default().primary.push(slot_number);
						}
						BabePreDigest::Secondary { .. } => {
							claims.entry(key.public()).or_default().secondary.push(slot_number);
						}
					};
				}
			}

			Ok(claims)
		}.then(|result| {
			let _ = tx.send(result).expect("receiever is never dropped; qed");
			ready(())
		}).boxed();

		self.threadpool.spawn_ok(future);

		Box::new(async {
			rx.await.expect("sender is never dropped; qed")
		}.boxed().compat())
	}
}

/// slot authorship information
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct SlotAuthorship {
	/// slot number in the epoch
	primary: Vec<u64>,
	/// claim data
	secondary: Vec<u64>,
}

/// Errors encountered by the RPC
#[derive(Debug, err_derive::Error, derive_more::From)]
pub enum Error {
	/// Consensus error
	#[error(display = "Consensus Error: {}", _0)]
	Consensus(ConsensusError),
	/// Errors that can be formatted as a String
	#[error(display = "{}", _0)]
	StringError(String)
}

impl From<Error> for jsonrpc_core::Error {
	fn from(error: Error) -> Self {
		jsonrpc_core::Error {
			message: format!("{}", error).into(),
			code: jsonrpc_core::ErrorCode::ServerError(1234),
			data: None,
		}
	}
}

/// fetches the epoch data for a given slot_number.
fn epoch_data<B, C, SC>(
	epoch_changes: &SharedEpochChanges<B>,
	client: &Arc<C>,
	babe_config: &Config,
	slot_number: u64,
	select_chain: &Arc<SC>,
) -> Result<Epoch, Error>
	where
		B: BlockT,
		C: HeaderBackend<B> + HeaderMetadata<B, Error=BlockChainError> + 'static,
		SC: SelectChain<B>,
{
	let parent = select_chain.best_chain()?;
	epoch_changes.lock().epoch_for_child_of(
		descendent_query(&**client),
		&parent.hash(),
		parent.number().clone(),
		slot_number,
		|slot| babe_config.genesis_epoch(slot),
	)
		.map_err(|e| Error::Consensus(ConsensusError::ChainLookup(format!("{:?}", e))))?
		.map(|e| e.into_inner())
		.ok_or(Error::Consensus(ConsensusError::InvalidAuthoritiesSet))
}
