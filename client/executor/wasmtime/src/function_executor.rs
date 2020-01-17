// Copyright 2019-2020 Parity Technologies (UK) Ltd.
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

use crate::instance_wrapper::InstanceWrapper;
use crate::util::checked_range;
use sc_executor_common::allocator::FreeingBumpHeapAllocator;
use sc_executor_common::error::{Error, Result};
use sc_executor_common::sandbox::{self, SandboxCapabilities, SupervisorFuncIndex};

use codec::{Decode, Encode};
use log::trace;
use sp_core::sandbox as sandbox_primitives;
use sp_wasm_interface::{
	MemoryId, Pointer, Result as WResult, Sandbox, Signature, Value, ValueType,
	WordSize,
};
use std::{cell::RefCell, cmp, mem, ptr, slice};
use wasmtime::{Func, Memory, Table, Val};

/// Wrapper type for pointer to a Wasm table entry.
///
/// The wrapper type is used to ensure that the function reference is valid as it must be unsafely
/// dereferenced from within the safe method `<HostContext as SandboxCapabilities>::invoke`.
#[derive(Clone)]
pub struct SupervisorFuncRef(Func);

/// The state required to construct a HostContext context. The context only lasts for one host
/// call, whereas the state is maintained for the duration of a Wasm runtime call, which may make
/// many different host calls that must share state.
pub struct HostState {
	sandbox_store: RefCell<sandbox::Store<SupervisorFuncRef>>,
	allocator: RefCell<FreeingBumpHeapAllocator>,
	instance: InstanceWrapper,
}

impl HostState {
	/// Constructs a new `HostState`.
	pub fn new(allocator: FreeingBumpHeapAllocator, instance: InstanceWrapper) -> Self {
		HostState {
			sandbox_store: RefCell::new(sandbox::Store::new()),
			allocator: RefCell::new(allocator),
			instance,
		}
	}

	pub fn into_instance(self) -> InstanceWrapper {
		self.instance
	}

	pub fn materialize(&self) -> HostContext {
		HostContext(self)
	}
}

/// A `HostContext` implements `FunctionContext` for making host calls from a Wasmtime
/// runtime. The `HostContext` exists only for the lifetime of the call and borrows state from
/// a longer-living `HostState`.
pub struct HostContext<'a>(&'a HostState);

impl<'a> std::ops::Deref for HostContext<'a> {
	type Target = HostState;
	fn deref(&self) -> &HostState {
		self.0
	}
}

impl<'a> SandboxCapabilities for HostContext<'a> {
	type SupervisorFuncRef = SupervisorFuncRef;

	fn allocate(&mut self, len: WordSize) -> Result<Pointer<u8>> {
		self.instance
			.allocate(&mut *self.allocator.borrow_mut(), len)
	}

	fn deallocate(&mut self, ptr: Pointer<u8>) -> Result<()> {
		self.instance
			.deallocate(&mut *self.allocator.borrow_mut(), ptr)
	}

	fn write_memory(&mut self, ptr: Pointer<u8>, data: &[u8]) -> Result<()> {
		self.instance.write_memory_from(ptr, data)
	}

	fn read_memory(&self, ptr: Pointer<u8>, len: WordSize) -> Result<Vec<u8>> {
		let mut output = vec![0; len as usize];
		self.instance.read_memory_into(ptr, output.as_mut())?;
		Ok(output)
	}

	fn invoke(
		&mut self,
		dispatch_thunk: &Self::SupervisorFuncRef,
		invoke_args_ptr: Pointer<u8>,
		invoke_args_len: WordSize,
		state: u32,
		func_idx: SupervisorFuncIndex,
	) -> Result<i64> {
		let result = dispatch_thunk.0.call(&[
			Val::I32(u32::from(invoke_args_ptr) as i32),
			Val::I32(invoke_args_len as i32),
			Val::I32(state as i32),
			Val::I32(usize::from(func_idx) as i32),
		]);
		match result {
			Ok(ret_vals) => {
				let ret_val = if ret_vals.len() != 1 {
					return Err(format!(
						"Supervisor function returned {} results, expected 1",
						ret_vals.len()
					)
					.into());
				} else {
					&ret_vals[0]
				};

				if let Some(ret_val) = ret_val.i64() {
					Ok(ret_val)
				} else {
					return Err("Supervisor function returned unexpected result!".into());
				}
			}
			Err(err) => Err(err.message().to_string().into()),
		}
	}
}

impl<'a> sp_wasm_interface::FunctionContext for HostContext<'a> {
	fn read_memory_into(&self, address: Pointer<u8>, dest: &mut [u8]) -> WResult<()> {
		self.instance
			.read_memory_into(address, dest)
			.map_err(|e| e.to_string())
	}

	fn write_memory(&mut self, address: Pointer<u8>, data: &[u8]) -> WResult<()> {
		self.instance
			.write_memory_from(address, data)
			.map_err(|e| e.to_string())
	}

	fn allocate_memory(&mut self, size: WordSize) -> WResult<Pointer<u8>> {
		self.instance
			.allocate(&mut *self.allocator.borrow_mut(), size)
			.map_err(|e| e.to_string())
	}

	fn deallocate_memory(&mut self, ptr: Pointer<u8>) -> WResult<()> {
		self.instance
			.deallocate(&mut *self.allocator.borrow_mut(), ptr)
			.map_err(|e| e.to_string())
	}

	fn sandbox(&mut self) -> &mut dyn Sandbox {
		self
	}
}

impl<'a> Sandbox for HostContext<'a> {
	fn memory_get(
		&mut self,
		memory_id: MemoryId,
		offset: WordSize,
		buf_ptr: Pointer<u8>,
		buf_len: WordSize,
	) -> WResult<u32> {
		let sandboxed_memory = self
			.sandbox_store
			.borrow()
			.memory(memory_id)
			.map_err(|e| e.to_string())?;
		sandboxed_memory.with_direct_access(|sandboxed_memory| {
			let len = buf_len as usize;
			let src_range = match checked_range(offset as usize, len, sandboxed_memory.len()) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			let supervisor_mem_size = self.instance.memory_size() as usize;
			let dst_range = match checked_range(buf_ptr.into(), len, supervisor_mem_size) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			self.instance
				.write_memory_from(
					Pointer::new(dst_range.start as u32),
					&sandboxed_memory[src_range],
				)
				.expect("ranges are checked above; write can't fail; qed");
			Ok(sandbox_primitives::ERR_OK)
		})
	}

	fn memory_set(
		&mut self,
		memory_id: MemoryId,
		offset: WordSize,
		val_ptr: Pointer<u8>,
		val_len: WordSize,
	) -> WResult<u32> {
		let sandboxed_memory = self
			.sandbox_store
			.borrow()
			.memory(memory_id)
			.map_err(|e| e.to_string())?;
		sandboxed_memory.with_direct_access_mut(|sandboxed_memory| {
			let len = val_len as usize;
			let supervisor_mem_size = self.instance.memory_size() as usize;
			let src_range = match checked_range(val_ptr.into(), len, supervisor_mem_size) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			let dst_range = match checked_range(offset as usize, len, sandboxed_memory.len()) {
				Some(range) => range,
				None => return Ok(sandbox_primitives::ERR_OUT_OF_BOUNDS),
			};
			self.instance
				.read_memory_into(
					Pointer::new(src_range.start as u32),
					&mut sandboxed_memory[dst_range],
				)
				.expect("ranges are checked above; read can't fail; qed");
			Ok(sandbox_primitives::ERR_OK)
		})
	}

	fn memory_teardown(&mut self, memory_id: MemoryId) -> WResult<()> {
		self.sandbox_store
			.borrow_mut()
			.memory_teardown(memory_id)
			.map_err(|e| e.to_string())
	}

	fn memory_new(&mut self, initial: u32, maximum: MemoryId) -> WResult<u32> {
		self.sandbox_store
			.borrow_mut()
			.new_memory(initial, maximum)
			.map_err(|e| e.to_string())
	}

	fn invoke(
		&mut self,
		instance_id: u32,
		export_name: &str,
		args: &[u8],
		return_val: Pointer<u8>,
		return_val_len: u32,
		state: u32,
	) -> WResult<u32> {
		trace!(target: "sp-sandbox", "invoke, instance_idx={}", instance_id);

		// Deserialize arguments and convert them into wasmi types.
		let args = Vec::<sandbox_primitives::TypedValue>::decode(&mut &args[..])
			.map_err(|_| "Can't decode serialized arguments for the invocation")?
			.into_iter()
			.map(Into::into)
			.collect::<Vec<_>>();

		let instance = self
			.sandbox_store
			.borrow()
			.instance(instance_id)
			.map_err(|e| e.to_string())?;
		let result = instance.invoke(export_name, &args, self, state);

		match result {
			Ok(None) => Ok(sandbox_primitives::ERR_OK),
			Ok(Some(val)) => {
				// Serialize return value and write it back into the memory.
				sandbox_primitives::ReturnValue::Value(val.into()).using_encoded(|val| {
					if val.len() > return_val_len as usize {
						Err("Return value buffer is too small")?;
					}
					HostContext::write_memory(self, return_val, val).map_err(|_| "can't write return value")?;
					Ok(sandbox_primitives::ERR_OK)
				})
			}
			Err(_) => Ok(sandbox_primitives::ERR_EXECUTION),
		}
	}

	fn instance_teardown(&mut self, instance_id: u32) -> WResult<()> {
		self.sandbox_store
			.borrow_mut()
			.instance_teardown(instance_id)
			.map_err(|e| e.to_string())
	}

	fn instance_new(
		&mut self,
		dispatch_thunk_id: u32,
		wasm: &[u8],
		raw_env_def: &[u8],
		state: u32,
	) -> WResult<u32> {
		// Extract a dispatch thunk from the instance's table by the specified index.
		let dispatch_thunk = {
			let table_item = self
				.instance
				.table()
				.as_ref()
				.ok_or_else(|| "Runtime doesn't have a table; sandbox is unavailable")?
				.get(dispatch_thunk_id);

			let func_ref = table_item
				.funcref()
				.ok_or_else(|| "dispatch_thunk_idx should be a funcref")?
				.clone();
			SupervisorFuncRef(func_ref)
		};

		let guest_env =
			match sandbox::GuestEnvironment::decode(&*self.sandbox_store.borrow(), raw_env_def) {
				Ok(guest_env) => guest_env,
				Err(_) => return Ok(sandbox_primitives::ERR_MODULE as u32),
			};

		let instance_idx_or_err_code =
			match sandbox::instantiate(self, dispatch_thunk, wasm, guest_env, state)
				.map(|i| i.finalize(&mut *self.sandbox_store.borrow_mut()))
			{
				Ok(instance_idx) => instance_idx,
				Err(sandbox::InstantiationError::StartTrapped) => sandbox_primitives::ERR_EXECUTION,
				Err(_) => sandbox_primitives::ERR_MODULE,
			};

		Ok(instance_idx_or_err_code as u32)
	}
}
