//! Interop vectors produced by a real sender library (see `source` in the JSON).

use pushharbor_core::vapid::verify;
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    sub: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    authorization: String,
    audience: String,
    now: u64,
    max_lifetime: u64,
    expect: String,
}

#[test]
fn vapid_vectors() {
    let file: File = serde_json::from_str(include_str!("vectors/vapid.json")).unwrap();
    for v in file.vectors {
        let got = verify(&v.authorization, &v.audience, v.now, v.max_lifetime);
        match (v.expect.as_str(), got) {
            ("ok", Ok(vapid)) => assert_eq!(vapid.sub, file.sub, "{}", v.name),
            (want, Err(err)) => assert_eq!(format!("{err:?}"), want, "{}", v.name),
            (want, got) => panic!("{}: want {want}, got {got:?}", v.name),
        }
    }
}
