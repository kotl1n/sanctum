//! Изоляция хранилища Windows: DACL владельца, DPAPI пользователя и дерево процессов.

use crate::{Error, Result};
use std::{
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
            SetNamedSecurityInfoW,
        },
        Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    },
};
use zeroize::{Zeroize, Zeroizing};

pub fn protect_path(path: &Path) -> Result<()> {
    if crate::platform::reparse_path(path) {
        return Err(Error("private_path_reparse_point"));
    }
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // OWNER RIGHTS и SYSTEM; наследование только в пределах приватного каталога.
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(Error("private_acl_failed"));
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = ptr::null_mut();
        let valid = GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted)
            != 0
            && present != 0
            && !acl.is_null();
        let applied = valid
            && SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null_mut(),
            ) == 0;
        LocalFree(descriptor);
        if !applied {
            return Err(Error("private_acl_failed"));
        }
    }
    Ok(())
}

pub fn check_file(file: &std::fs::File) -> Result<()> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.dwFileAttributes & 0x400 != 0
        || info.nNumberOfLinks != 1
    {
        return Err(Error("private_file_required"));
    }
    Ok(())
}

pub fn key_blob(bytes: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() > 65536 {
        return Err(Error("invalid_vault_key"));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    let success = unsafe {
        if protect {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if success == 0 {
        return Err(Error("vault_dpapi_failed"));
    }
    unsafe {
        if output.pbData.is_null() || output.cbData > 65536 {
            LocalFree(output.pbData.cast());
            return Err(Error("invalid_vault_key"));
        }
        let memory = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let result = Zeroizing::new(memory.to_vec());
        memory.zeroize();
        LocalFree(output.pbData.cast());
        Ok(result)
    }
}

pub struct ProcessTree(HANDLE);
impl ProcessTree {
    pub fn attach(child: &std::process::Child) -> Result<Self> {
        let job = Self(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) });
        if job.0.is_null() {
            return Err(Error("local_job_failed"));
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
            || unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) } == 0
        {
            return Err(Error("local_job_failed"));
        }
        Ok(job)
    }
}
impl Drop for ProcessTree {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
