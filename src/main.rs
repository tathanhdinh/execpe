// cargo build --release --target i686-pc-windows-msvc

#![windows_subsystem = "console"]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate winapi;
#[macro_use] extern crate structopt;
#[macro_use] extern crate failure;

use std::{result, path, ffi::OsString, os::windows::ffi::OsStrExt, iter, ptr, mem};
use failure::Error;
use structopt::StructOpt;
use winapi::um::{processthreadsapi::{CreateProcessW, STARTUPINFOW, PROCESS_INFORMATION}, errhandlingapi::GetLastError, winnt};

type Result<T> = result::Result<T, Error>;

#[derive(StructOpt, Debug)]
#[structopt(name = "execpe")]
struct ExecPeArg {
    #[structopt(name = "pe file", 
                parse(from_os_str), 
                help = "PE file to execute")]
    pe_file: path::PathBuf,
}

fn main() -> Result<()> {
    let ret = unsafe {
        let arg = ExecPeArg::from_args();
        let pe_name = OsString::from(arg.pe_file).encode_wide()
                                                 .chain(iter::once(0))
                                                 .collect::<Vec<u16>>();

        let mut startupInfo: STARTUPINFOW = mem::zeroed();
        let mut processInfo: PROCESS_INFORMATION = mem::zeroed();

        CreateProcessW(ptr::null_mut(),                   // lpApplicationName
                       pe_name.as_ptr() as winnt::LPWSTR, // lpCommandLine
                       ptr::null_mut(),                   // lpProcessAttributes
                       ptr::null_mut(),                   // lpThreadAttributes
                       0,                                 // bInheritHandles
                       0,                                 // dwCreationFlags
                       ptr::null_mut(),                   // lpEnvironment
                       ptr::null_mut(),                   // lpCurrentDirectory
                       &mut startupInfo,                  // lpStartupInfo
                       &mut processInfo)                  // lpProcessInformation
    };

    if ret == 0 {
        let last_err_code = unsafe { GetLastError() };
        return Err(format_err!("cannot execute PE file (error code: {})", last_err_code))
    }

    Ok(())
}
