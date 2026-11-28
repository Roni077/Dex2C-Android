//! Android system resource IDs (attributes) - inverse map id -> name.
//! IDs must match frameworks/base `public.xml` / `android.R.attr` — PackageManager
//! binary-searches manifest attributes by these IDs.

use once_cell::sync::Lazy;
use std::collections::HashMap;

pub const ANDROID_NS_URI: &str = "http://schemas.android.com/apk/res/android";

static ATTR_INVERSE: Lazy<HashMap<u32, String>> = Lazy::new(build_attr_inverse);
static ATTR_FORWARD: Lazy<HashMap<String, u32>> = Lazy::new(|| {
    ATTR_INVERSE
        .iter()
        .map(|(id, name)| (name.clone(), *id))
        .collect()
});

fn build_attr_inverse() -> HashMap<u32, String> {
    let mut m = HashMap::new();
    let attrs = [
        (16842752u32, "theme"),
        (16842753, "label"),
        (16842754, "icon"),
        (16842755, "name"),
        (16842756, "manageSpaceActivity"),
        (16842757, "allowClearUserData"),
        (16842758, "permission"),
        (16842759, "readPermission"),
        (16842760, "writePermission"),
        (16842761, "protectionLevel"),
        (16842762, "permissionGroup"),
        (16842763, "sharedUserId"),
        (16842764, "hasCode"),
        (16842765, "persistent"),
        (16842766, "enabled"),
        (16842767, "debuggable"),
        (16842768, "exported"),
        (16842769, "process"),
        (16842770, "taskAffinity"),
        (16842771, "multiprocess"),
        (16842772, "finishOnTaskLaunch"),
        (16842773, "clearTaskOnLaunch"),
        (16842774, "stateNotNeeded"),
        (16842775, "excludeFromRecents"),
        (16842776, "authorities"),
        (16842777, "syncable"),
        (16842778, "initOrder"),
        (16842779, "grantUriPermissions"),
        (16842780, "priority"),
        (16842781, "launchMode"),
        (16842782, "screenOrientation"),
        (16842783, "configChanges"),
        (16842784, "description"),
        (16842785, "targetPackage"),
        (16842786, "handleProfiling"),
        (16842787, "functionalTest"),
        (16842788, "value"),
        (16842789, "resource"),
        (16842790, "mimeType"),
        (16842791, "scheme"),
        (16842792, "host"),
        (16842793, "port"),
        (16842794, "path"),
        (16842795, "pathPrefix"),
        (16842796, "pathPattern"),
        (16842797, "action"),
        (16842798, "data"),
        (16842799, "targetClass"),
        (16842960, "id"),
        (16842961, "tag"),
        (16842972, "visibility"),
        (16842996, "layout_width"),
        (16842997, "layout_height"),
        (16843071, "text"),
        (16843072, "hint"),
        (16843276, "minSdkVersion"),
        (16843291, "versionCode"),
        (16843292, "versionName"),
        (16843307, "windowSoftInputMode"),
        (16843372, "anyDensity"),
        (16843376, "targetSdkVersion"),
        (16843377, "maxSdkVersion"),
        (16843392, "allowBackup"),
        (16843406, "required"),
        (16843447, "installLocation"),
        (16843475, "hardwareAccelerated"),
        (16843687, "parentActivityName"),
        (16843695, "supportsRtl"),
        (16844010, "extractNativeLibs"),
        (16844012, "usesCleartextTraffic"),
        (16844037, "directBootAware"),
        (16844146, "compileSdkVersion"),
        (16844147, "compileSdkVersionCodename"),
        (16844154, "appComponentFactory"),
    ];
    for (id, name) in attrs {
        m.insert(id, name.to_string());
    }
    m
}

pub fn get_attr_name(res_id: u32) -> Option<&'static str> {
    ATTR_INVERSE.get(&res_id).map(|s| s.as_str())
}

pub fn attribute_id_to_name(res_id: u32) -> Option<String> {
    ATTR_INVERSE.get(&res_id).cloned()
}

/// Resolve android attribute local name → resource id (for AXML resource map).
pub fn attr_name_to_id(name: &str) -> Option<u32> {
    let name = name.strip_prefix("android:").unwrap_or(name);
    ATTR_FORWARD.get(name).copied()
}
