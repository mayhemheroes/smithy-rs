/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#![no_main]

use aws_smithy_eventstream::frame::Message;
use libfuzzer_sys::fuzz_target;

const EXPECTED_ERRORS: [&str; 5] = [
    "HeadersTooLong",
    "PayloadTooLong",
    "MessageTooLong",
    "InvalidHeaderNameLength",
    "TimestampValueTooLarge",
];

fuzz_target!(|message: Message| {
    let mut buffer = Vec::new();
    match message.write_to(&mut buffer) {
        Err(err) => {
            let err_dbg = format!("{err:?}");
            if !EXPECTED_ERRORS.iter().any(|e| e.contains(&err_dbg)) {
                panic!("unexpected error on write: {}", err)
            }
        }
        Ok(_) => {
            let mut data = &buffer[..];
            let parsed = Message::read_from(&mut data).unwrap();
            assert_eq!(message, parsed);
        }
    }
});
