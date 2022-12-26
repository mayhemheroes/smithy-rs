/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#![no_main]

use aws_smithy_eventstream::frame::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|message: Message| {
    let mut buffer = Vec::new();
    if message.write_to(&mut buffer).is_ok() {
        let mut data = &buffer[..];
        let parsed = Message::read_from(&mut data).unwrap();
        assert_eq!(message, parsed);
    }
});
