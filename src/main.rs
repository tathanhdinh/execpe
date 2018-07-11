#![windows_subsystem = "console"]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate winapi;
#[macro_use] extern crate structopt;
#[macro_use] extern crate failure;

use std::{result, path, ffi::OsString, os::windows::ffi::OsStrExt, iter, ptr};
use failure::Error;
use structopt::StructOpt;
use winapi::um::{processthreadsapi::CreateProcessW, errhandlingapi::GetLastError};

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
        let lpApplicationName = OsString::from(arg.pe_file).encode_wide()
                                                           .chain(iter::once(0))
                                                           .collect::<Vec<u16>>();
        CreateProcessW(lpApplicationName.as_ptr(), 
                       ptr::null_mut(),     // lpCommandLine
                       ptr::null_mut(),     // lpProcessAttributes
                       ptr::null_mut(),     // lpThreadAttributes
                       0,                   // bInheritHandles
                       0,                   // dwCreationFlags
                       ptr::null_mut(),     // lpEnvironment
                       ptr::null_mut(),     // lpCurrentDirectory
                       ptr::null_mut(),     // lpStartupInfo
                       ptr::null_mut())     // lpProcessInformation
    };

    if ret == 0 {
        let last_err_code = unsafe {
            GetLastError()
        };
        return Err(format_err!("cannot execute PE file (error code: {})", last_err_code))
    }

    Ok(())
}
