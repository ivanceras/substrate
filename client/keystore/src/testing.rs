// Copyright 2017-2020 Parity Technologies (UK) Ltd.
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
// along with Substrate. If not, see <http://www.gnu.org/licenses/>.

//! Testing Utilities for Keystore

use crate::{KeyStorePtr, Store};
use sp_keyring::Ed25519Keyring;
use sp_application_crypto::AppPair;

/// creates keystore backed by a temp file
pub fn create_temp_keystore<P: AppPair>(authority: Ed25519Keyring) -> (KeyStorePtr, tempfile::TempDir) {
	let keystore_path = tempfile::tempdir().expect("Creates keystore path");
	let keystore = Store::open(keystore_path.path(), None).expect("Creates keystore");
	keystore.write().insert_ephemeral_from_seed::<P>(&authority.to_seed())
		.expect("Creates authority key");

	(keystore, keystore_path)
}