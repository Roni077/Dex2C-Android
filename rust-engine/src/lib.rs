//! JNI Bridge Exports for Dex2C Studio's Rust Native Backend Engine.
//! Provides panic-guarded, zero-copy native acceleration to the Kotlin Android layer.

pub mod apk_inspector;
pub mod apk_signer;
pub mod decompiler_bridge;
pub mod dex;
pub mod disasm_bridge;
pub mod editor;
pub mod filter;

use apk_inspector::{
    inspect_apk_archive_json, inspect_manifest_and_resources_json, split_dex041_container,
};
use apk_signer::align_and_sign_apk_bytes;
use decompiler_bridge::{decompile_class_java, decompile_method_java};
use dex::{pack_dex_classes, DexFile};
use dex2c_core::TranspilerConfig;
use dex2c_dex::{
    evaluate_dex_methods_and_classes, verify_dex_class_json, verify_dex_method_json,
};
use dex2c_smali::SmaliDisassembler;
use dex2c_toolchain::{generate_android_mk, generate_application_mk, generate_cmakelists};
use dex2c_transpiler::{generate_runtime_header, CppEmitter};
use disasm_bridge::disassemble_method_to_json;
use filter::evaluate_dex_methods;
use jni::objects::{JByteArray, JClass, JIntArray, JObject, JObjectArray, JString};
use jni::sys::{
    jboolean, jbyteArray, jint, jintArray, jlong, jobject, jobjectArray, jsize, jstring, JNI_TRUE,
};
use jni::JNIEnv;
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

struct DexHolder {
    buffer: Vec<u8>,
    dex: DexFile,
    cached_packed: Option<Vec<u8>>,
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeOpenDex(
    env: JNIEnv,
    _class: JClass,
    bytes_array: JByteArray,
    size: jsize,
) -> jlong {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if bytes_array.is_null() || size <= 0x70 {
            return 0i64;
        }

        let mut buffer = vec![0u8; size as usize];
        let slice_i8: &mut [i8] =
            std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut i8, buffer.len());
        if env.get_byte_array_region(&bytes_array, 0, slice_i8).is_err() {
            return 0i64;
        }

        let dex = match DexFile::parse(&buffer) {
            Ok(d) => d,
            Err(_) => return 0i64,
        };

        let holder = Box::new(DexHolder {
            buffer,
            dex,
            cached_packed: None,
        });

        Box::into_raw(holder) as jlong
    }));

    result.unwrap_or(0i64)
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeCloseDex(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _ = Box::from_raw(handle as *mut DexHolder);
    }));
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeGetClassCount(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        holder.dex.header.class_defs_size as jint
    }));
    result.unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeGetStringCount(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return 0;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        holder.dex.header.string_ids_size as jint
    }));
    result.unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeParseDex(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jobject {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &mut *(handle as *mut DexHolder);
        if holder.cached_packed.is_none() {
            holder.cached_packed = Some(pack_dex_classes(&holder.dex));
        }

        let packed = holder.cached_packed.as_mut().unwrap();
        let buf = match env.new_direct_byte_buffer(packed.as_mut_ptr(), packed.len()) {
            Ok(b) => b,
            Err(_) => return std::ptr::null_mut(),
        };

        buf.into_raw()
    }));

    result.unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeFilterMethods(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    rules_array: JObjectArray,
    allow_init: jboolean,
    skip_synthetic: jboolean,
) -> jintArray {
    if handle == 0 || rules_array.is_null() {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let rule_strings = read_jstring_array(&mut env, &rules_array)?;
        let rust_rules: Vec<&str> = rule_strings.iter().map(|s| s.as_str()).collect();

        let matched = evaluate_dex_methods(
            &holder.dex,
            &rust_rules,
            allow_init == JNI_TRUE,
            skip_synthetic == JNI_TRUE,
        );

        let out_array = env.new_int_array(matched.len() as jsize).ok()?;
        env.set_int_array_region(&out_array, 0, &matched).ok()?;
        Some(out_array.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeFilterClassesAndMethods(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    rules_array: JObjectArray,
    allow_init: jboolean,
    skip_synthetic: jboolean,
) -> jintArray {
    if handle == 0 || rules_array.is_null() {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let rule_strings = read_jstring_array(&mut env, &rules_array)?;
        let rust_rules: Vec<&str> = rule_strings.iter().map(|s| s.as_str()).collect();

        let matched = evaluate_dex_methods_and_classes(
            &holder.dex,
            &rust_rules,
            allow_init == JNI_TRUE,
            skip_synthetic == JNI_TRUE,
        );

        let total_size = 2 + matched.matched_classes.len() + matched.matched_methods.len();
        let mut packed = Vec::with_capacity(total_size);
        packed.push(matched.matched_classes.len() as i32);
        packed.push(matched.matched_methods.len() as i32);
        packed.extend_from_slice(&matched.matched_classes);
        packed.extend_from_slice(&matched.matched_methods);

        let out_array = env.new_int_array(packed.len() as jsize).ok()?;
        env.set_int_array_region(&out_array, 0, &packed).ok()?;
        Some(out_array.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeDisassembleClassSmali(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    class_def_idx: jint,
) -> jstring {
    if handle == 0 || class_def_idx < 0 {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let cls = holder.dex.get_class_def_full(class_def_idx as u32)?;
        let smali_text = SmaliDisassembler::disassemble_class(&holder.dex, &cls);
        env.new_string(smali_text).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeDisassembleMethodJson(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    class_def_idx: jint,
    method_idx: jint,
) -> jstring {
    if handle == 0 || class_def_idx < 0 || method_idx < 0 {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let json_str =
            disassemble_method_to_json(&holder.dex, class_def_idx as u32, method_idx as u32)?;
        env.new_string(json_str).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeTranspileMethod(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    class_def_idx: jint,
    method_idx: jint,
) -> jstring {
    if handle == 0 || class_def_idx < 0 || method_idx < 0 {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let cls = holder.dex.get_class_def_full(class_def_idx as u32)?;
        let m = cls
            .direct_methods
            .iter()
            .chain(cls.virtual_methods.iter())
            .find(|method| method.method_idx == method_idx as u32)?;

        let config = TranspilerConfig::default();
        let emitter = CppEmitter::new(&holder.dex, &config);
        let cpp_code = emitter.transpile_method(&cls, m);
        env.new_string(cpp_code).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativePatchDexMethods(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    method_indices_array: JIntArray,
) -> jint {
    if handle == 0 || method_indices_array.is_null() {
        return -1;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &mut *(handle as *mut DexHolder);
        let len = match env.get_array_length(&method_indices_array) {
            Ok(l) => l as usize,
            Err(_) => return -1,
        };

        let mut method_ids = vec![0i32; len];
        if env
            .get_int_array_region(&method_indices_array, 0, &mut method_ids)
            .is_err()
        {
            return -1;
        }

        let set: HashSet<u32> = method_ids.into_iter().map(|id| id as u32).collect();
        match dex2c_dex::patch_dex_methods_native(&mut holder.buffer, &set) {
            Ok(count) => {
                holder.cached_packed = None;
                if let Ok(updated) = DexFile::parse(&holder.buffer) {
                    holder.dex = updated;
                }
                count as jint
            }
            Err(_) => -1,
        }
    }));

    result.unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeGenerateBuildFiles(
    mut env: JNIEnv,
    _class: JClass,
    module_name_jstr: JString,
    source_files_array: JObjectArray,
) -> jstring {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let module_name = if !module_name_jstr.is_null() {
            env.get_string(&module_name_jstr)
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "dex2c_native".into())
        } else {
            "dex2c_native".into()
        };

        let mut config = TranspilerConfig::default();
        config.module_name = module_name.clone();

        let sources = if source_files_array.is_null() {
            Vec::new()
        } else {
            read_jstring_array(&mut env, &source_files_array).unwrap_or_default()
        };

        let cmake = generate_cmakelists(&config, &sources);
        let android_mk = generate_android_mk(&config, &sources);
        let app_mk = generate_application_mk(&["arm64-v8a", "x86_64"]);
        let header = generate_runtime_header(&module_name);

        let json = serde_json::json!({
            "cmake": cmake,
            "android_mk": android_mk,
            "application_mk": app_mk,
            "runtime_header": header
        });

        env.new_string(json.to_string())
            .ok()
            .map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeInspectManifestAndResources(
    env: JNIEnv,
    _class: JClass,
    manifest_bytes: JByteArray,
    arsc_bytes: JByteArray,
) -> jstring {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if manifest_bytes.is_null() {
            return None;
        }
        let manifest_vec = env.convert_byte_array(&manifest_bytes).ok()?;
        let arsc_vec = if arsc_bytes.is_null() {
            None
        } else {
            env.convert_byte_array(&arsc_bytes).ok()
        };
        let json_str = inspect_manifest_and_resources_json(&manifest_vec, arsc_vec.as_deref())?;
        env.new_string(json_str).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeInspectApkArchive(
    env: JNIEnv,
    _class: JClass,
    apk_bytes: JByteArray,
) -> jstring {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if apk_bytes.is_null() {
            return None;
        }
        let apk_vec = env.convert_byte_array(&apk_bytes).ok()?;
        let json_str = inspect_apk_archive_json(&apk_vec)?;
        env.new_string(json_str).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeSplitDex041Container(
    mut env: JNIEnv,
    _class: JClass,
    entry_name_jstr: JString,
    dex_bytes: JByteArray,
) -> jobjectArray {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if dex_bytes.is_null() {
            return None;
        }
        let entry_name = if entry_name_jstr.is_null() {
            "classes.dex".to_string()
        } else {
            env.get_string(&entry_name_jstr)
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "classes.dex".to_string())
        };
        let dex_vec = env.convert_byte_array(&dex_bytes).ok()?;
        let sections = split_dex041_container(&entry_name, dex_vec);
        if sections.is_empty() {
            return None;
        }

        let byte_array_cls = env.find_class("[B").ok()?;
        let out_arr = env
            .new_object_array((sections.len() * 2) as jsize, byte_array_cls, JObject::null())
            .ok()?;

        for (idx, (label, bytes)) in sections.into_iter().enumerate() {
            let label_arr = env.byte_array_from_slice(label.as_bytes()).ok()?;
            let data_arr = env.byte_array_from_slice(&bytes).ok()?;
            env.set_object_array_element(&out_arr, (idx * 2) as jsize, label_arr)
                .ok()?;
            env.set_object_array_element(&out_arr, (idx * 2 + 1) as jsize, data_arr)
                .ok()?;
        }
        Some(out_arr.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeVerifyDexMethod(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    class_def_idx: jint,
    method_idx: jint,
) -> jstring {
    if handle == 0 || class_def_idx < 0 || method_idx < 0 {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let json_str = verify_dex_method_json(&holder.dex, class_def_idx as u32, method_idx as u32)?;
        env.new_string(json_str).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeVerifyDexClass(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    class_def_idx: jint,
) -> jstring {
    if handle == 0 || class_def_idx < 0 {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let json_str = verify_dex_class_json(&holder.dex, class_def_idx as u32)?;
        env.new_string(json_str).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeAlignAndSignApk(
    env: JNIEnv,
    _class: JClass,
    apk_bytes: JByteArray,
    private_key_der: JByteArray,
    cert_der: JByteArray,
    v1: jboolean,
    v2: jboolean,
    v3: jboolean,
    page_alignment: jint,
) -> jbyteArray {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if apk_bytes.is_null() {
            return None;
        }
        let apk_vec = env.convert_byte_array(&apk_bytes).ok()?;
        let pk_vec = if private_key_der.is_null() {
            None
        } else {
            env.convert_byte_array(&private_key_der).ok()
        };
        let cert_vec = if cert_der.is_null() {
            None
        } else {
            env.convert_byte_array(&cert_der).ok()
        };

        let signed = align_and_sign_apk_bytes(
            &apk_vec,
            pk_vec.as_deref(),
            cert_vec.as_deref(),
            v1 == JNI_TRUE,
            v2 == JNI_TRUE,
            v3 == JNI_TRUE,
            page_alignment.max(0) as u32,
        )
        .ok()?;

        env.byte_array_from_slice(&signed)
            .ok()
            .map(|a| a.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeDecompileMethodJava(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    class_def_idx: jint,
    method_idx: jint,
    arsc_bytes: JByteArray,
) -> jstring {
    if handle == 0 || class_def_idx < 0 || method_idx < 0 {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let arsc_vec = if arsc_bytes.is_null() {
            None
        } else {
            env.convert_byte_array(&arsc_bytes).ok()
        };
        let java_src = decompile_method_java(
            &holder.dex,
            class_def_idx as u32,
            method_idx as u32,
            arsc_vec.as_deref(),
        )?;
        env.new_string(java_src).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeDecompileClassJava(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    class_def_idx: jint,
    arsc_bytes: JByteArray,
) -> jstring {
    if handle == 0 || class_def_idx < 0 {
        return std::ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let holder = &*(handle as *const DexHolder);
        let arsc_vec = if arsc_bytes.is_null() {
            None
        } else {
            env.convert_byte_array(&arsc_bytes).ok()
        };
        let java_src = decompile_class_java(
            &holder.dex,
            class_def_idx as u32,
            arsc_vec.as_deref(),
        )?;
        env.new_string(java_src).ok().map(|s| s.into_raw())
    }));

    result.ok().flatten().unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_dex2c_studio_nativeengine_DexNativeEngine_nativeGetVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let s = env
        .new_string(
            "rust_dex2c 0.2.0 (androguard dex-parser + dex-bytecode + axml-parser + apkparser + dex-decompiler + SIMD RegexSet)",
        )
        .ok();
    s.map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn read_jstring_array(env: &mut JNIEnv, arr: &JObjectArray) -> Option<Vec<String>> {
    let len = env.get_array_length(arr).ok()?;
    let mut out = Vec::with_capacity(len.max(0) as usize);
    for i in 0..len {
        if let Ok(obj) = env.get_object_array_element(arr, i) {
            let jstr: JString = obj.into();
            if !jstr.is_null() {
                if let Ok(java_str) = env.get_string(&jstr) {
                    out.push(java_str.to_string_lossy().into_owned());
                }
            }
        }
    }
    Some(out)
}
