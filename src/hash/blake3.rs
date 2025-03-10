use std::collections::HashMap;

use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub use bitcoin_script::{define_pushable, script};
define_pushable!();
pub use bitcoin::ScriptBuf as Script;

use crate::table::stack_tables::{Operation, StackTables};

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MAX_MSG_SIZE_IMPL: u32 = 288;

const MSG_PERMUTATION: [u8; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

pub fn right_rotate_xored(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    x: u8,
    y: u8,
    n: u8,
    tables: &StackTables,
) -> StackVariable {
    let pos_shift = 8 - n / 4;

    let y = var_map[&y];
    let x = var_map[&x];

    for i in pos_shift..pos_shift + 8 {
        let n = i % 8;

        let mut z = 0;
        if i < 8 {
            z = pos_shift;
        }

        tables.apply_with_depth(stack, x, y, z, n);
    }

    stack.join_in_stack(8, None, Some("right_rotated_xored"))
}

pub fn right_rotate7_xored_sub(
    stack: &mut StackTracker,
    x: StackVariable,
    y: StackVariable,
    tables: &StackTables,
    n: u8,
) {
    stack.from_altstack();

    let r0 = tables.apply_with_depth(stack, x, y, 0, n);

    stack.rename(r0, &format!("z{}", n));
    stack.copy_var(r0);

    stack.to_altstack();

    // r7 r0 >> 3
    let w1 = tables.apply_shift_two_nibbles(stack, 3, true, None);
    stack.rename(w1, &format!("w{}", n + 1));
}

pub fn right_rotate7_xored(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    x: u8,
    y: u8,
    tables: &StackTables,
) -> StackVariable {
    // x    = x0 x1 x2 x3 x4 x5 x6 x7
    // y    = y0 y1 y2 y3 y4 y5 y6 y7
    // x^y = z
    // z             = z0 z1 z2 z3 z4 z5 z6 z7
    // rrot4( z )    = z7 z0 z1 z2 z3 z4 z5 z6
    // w = rrot7( z ) = (z6) z7 z0 z1 z2 z3 z4 z5 z6  >> 3

    let y = var_map[&y];
    let x = var_map[&x];

    // nib 6 xored

    let z6 = tables.apply_with_depth(stack, x, y, 6, 6);
    stack.rename(z6, "z6");

    // nib 6 copy saved
    stack.copy_var(z6);
    stack.to_altstack();

    //nib 7 xored
    let z7 = tables.apply_with_depth(stack, x, y, 6, 7);
    stack.rename(z7, "z7");
    stack.copy_var(z7);
    stack.to_altstack();

    // z6 z7 >> 3
    let w0 = tables.apply_shift_two_nibbles(stack, 3, true, None);
    stack.rename(w0, "w0");

    for i in 0..6 {
        right_rotate7_xored_sub(stack, x, y, tables, i);
    }

    stack.from_altstack();
    stack.from_altstack();

    let w7 = tables.apply_shift_two_nibbles(stack, 3, true, None);
    stack.rename(w7, "w7");

    stack.join_count(w0, 7)
}

pub fn u4_add_direct(
    stack: &mut StackTracker,
    nibble_count: u32,
    to_copy: Vec<StackVariable>,
    to_move: Vec<StackVariable>,
    mut constants: Vec<u32>,
    tables: &StackTables,
) {
    // add all the constants together
    if constants.len() > 1 {
        let mut sum: u32 = 0;
        for c in constants.iter() {
            sum = sum.wrapping_add(*c);
        }
        constants = vec![sum];
    }

    //split the parts of the constant (still one element)
    let mut constant_parts: Vec<Vec<u32>> = Vec::new();
    for n in constants {
        let parts = (0..8).rev().map(|i| (n >> (i * 4)) & 0xF).collect();
        constant_parts.push(parts);
    }

    let number_count = to_copy.len() + to_move.len() + constant_parts.len();

    for i in (0..nibble_count).rev() {
        //copy the nibbles from the back
        for x in to_copy.iter() {
            stack.copy_var_sub_n(*x, i);
        }

        for x in to_move.iter() {
            stack.move_var_sub_n(*x, i);
        }

        for parts in constant_parts.iter() {
            stack.number(parts[i as usize]);
        }

        //add the numbers
        for _ in 0..number_count - 1 {
            stack.op_add();
        }

        //add the carry of the previous addition
        if i < nibble_count - 1 {
            stack.op_add();
        }

        if i > 0 {
            //dup the result to be used to get the carry except for the last nibble
            stack.op_dup();
        }

        //save value
        let modulo = stack.get_value_from_table(tables.modulo, None);
        stack.rename(modulo, &format!("modulo[{}]", i).to_string());
        stack.to_altstack();

        if i > 0 {
            let carry = stack.get_value_from_table(tables.quotient, None);
            stack.rename(carry, "carry");
        }
    }
}

pub fn g(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    mx: StackVariable,
    my: StackVariable,
    tables: &StackTables,
    last_round: bool,
) {
    //adds a + b + mx
    //consumes a and mx and copies b
    let vb = var_map[&b];
    let va = var_map.get_mut(&a).unwrap();

    if last_round {
        u4_add_direct(stack, 8, vec![vb], vec![*va, mx], vec![], tables);
    } else {
        u4_add_direct(stack, 8, vec![vb, mx], vec![*va], vec![], tables);
    }

    //stores the results in a
    *va = stack.from_altstack_joined(8, &format!("state_{}", a));

    // right rotate d xor a ( consumes d and copies a)
    let ret = right_rotate_xored(stack, var_map, d, a, 16, tables);
    // saves in d
    var_map.insert(d, ret);

    let vd = var_map[&d];
    let vc = var_map.get_mut(&c).unwrap();
    u4_add_direct(stack, 8, vec![vd], vec![*vc], vec![], tables);
    *vc = stack.from_altstack_joined(8, &format!("state_{}", c));

    let ret = right_rotate_xored(stack, var_map, b, c, 12, tables);
    var_map.insert(b, ret);

    let vb = var_map[&b];
    let va = var_map.get_mut(&a).unwrap();

    if last_round {
        u4_add_direct(stack, 8, vec![vb], vec![*va, my], vec![], tables);
    } else {
        u4_add_direct(stack, 8, vec![vb, my], vec![*va], vec![], tables);
    }

    *va = stack.from_altstack_joined(8, &format!("state_{}", a));

    let ret = right_rotate_xored(stack, var_map, d, a, 8, tables);
    var_map.insert(d, ret);
    stack.rename(ret, &format!("state_{}", d));

    let vd = var_map[&d];
    let vc = var_map.get_mut(&c).unwrap();
    u4_add_direct(stack, 8, vec![vd], vec![*vc], vec![], tables);
    *vc = stack.from_altstack_joined(8, &format!("state_{}", c));

    let ret = right_rotate7_xored(stack, var_map, b, c, tables);
    var_map.insert(b, ret);
    stack.rename(ret, &format!("state_{}", b));
}

pub fn round(
    stack: &mut StackTracker,
    state_var_map: &mut HashMap<u8, StackVariable>,
    message_var_map: &HashMap<u8, StackVariable>,
    tables: &StackTables,
    last_round: bool,
) {
    g(
        stack,
        state_var_map,
        0,
        4,
        8,
        12,
        message_var_map[&0],
        message_var_map[&1],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        1,
        5,
        9,
        13,
        message_var_map[&2],
        message_var_map[&3],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        2,
        6,
        10,
        14,
        message_var_map[&4],
        message_var_map[&5],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        3,
        7,
        11,
        15,
        message_var_map[&6],
        message_var_map[&7],
        tables,
        last_round,
    );

    g(
        stack,
        state_var_map,
        0,
        5,
        10,
        15,
        message_var_map[&8],
        message_var_map[&9],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        1,
        6,
        11,
        12,
        message_var_map[&10],
        message_var_map[&11],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        2,
        7,
        8,
        13,
        message_var_map[&12],
        message_var_map[&13],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        3,
        4,
        9,
        14,
        message_var_map[&14],
        message_var_map[&15],
        tables,
        last_round,
    );
}

pub fn permutate(message_var_map: &HashMap<u8, StackVariable>) -> HashMap<u8, StackVariable> {
    let mut ret = HashMap::new();
    for i in 0..16 as u8 {
        ret.insert(i, message_var_map[&MSG_PERMUTATION[i as usize]]);
    }
    ret
}

pub fn init_state(
    stack: &mut StackTracker,
    chaining: bool,
    counter: u32,
    block_len: u32,
    flags: u32,
) -> HashMap<u8, StackVariable> {
    let mut state = Vec::new();

    if chaining {
        for i in 0..8 {
            state.push(stack.from_altstack_joined(8, &format!("prev-hash[{}]", i)));
        }
    } else {
        for i in 0..8 {
            state.push(stack.number_u32(IV[i]));
        }
    }
    for i in 0..4 {
        state.push(stack.number_u32(IV[i]));
    }
    state.push(stack.number_u32(0));
    state.push(stack.number_u32(counter));
    state.push(stack.number_u32(block_len));
    state.push(stack.number_u32(flags));

    let mut state_map = HashMap::new();
    for i in 0..16 {
        state_map.insert(i as u8, state[i]);
        stack.rename(state[i], &format!("state_{}", i));
    }
    state_map
}

pub fn compress(
    stack: &mut StackTracker,
    chaining: bool,
    counter: u32,
    block_len: u32,
    flags: u32,
    mut message: HashMap<u8, StackVariable>,
    tables: &StackTables,
    final_rounds: u8,
    last_round: bool,
) {
    //chaining value needs to be copied for multiple blocks
    //every time that is provided

    let mut state = init_state(stack, chaining, counter, block_len, flags);

    for i in 0..7 {
        //round 6 could consume the message
        round(stack, &mut state, &message, tables, i == 6);

        if i == 6 {
            break;
        }
        message = permutate(&message);
    }

    for i in (0..final_rounds).rev() {
        let mut tmp = Vec::new();

        //iterate nibbles
        for n in 0..8 {
            let v2 = state.get(&(i + 8)).unwrap().clone();
            let v1 = state.get(&i).unwrap().clone();
            tmp.push(tables.apply_with_depth(stack, v1, v2, 0, n));

            if last_round {
                if n % 2 == 1 {
                    stack.to_altstack();
                    stack.to_altstack();
                }
            }
        }
        if !last_round {
            for _ in 0..8 {
                stack.to_altstack();
            }
        }
    }
}

pub fn get_flags_for_block(i: u32, num_blocks: u32) -> u32 {
    if num_blocks == 1 {
        return 0b00001011;
    }
    if i == 0 {
        return 0b00000001;
    }
    if i == num_blocks - 1 {
        return 0b00001010;
    }
    0
}

pub fn tables_for_blake3(stack: &mut StackTracker, use_full_tables: bool) -> StackTables {
    StackTables::new()
        .depth_lookup(stack, use_full_tables, false)
        .operation(stack, &Operation::Xor, use_full_tables)
        .rot_operation(stack, 3, true)
        .addition_operation(stack, 48)
}

pub fn to_le(stack: &mut StackTracker, var: StackVariable) -> StackVariable {
    let le_0 = stack.move_var_sub_n(var, 6);
    stack.move_var_sub_n(var, 6);
    stack.move_var_sub_n(var, 4);
    stack.move_var_sub_n(var, 4);
    stack.move_var_sub_n(var, 2);
    stack.move_var_sub_n(var, 2);
    stack.move_var_sub_n(var, 0);
    stack.move_var_sub_n(var, 0);
    stack.join_count(le_0, 7)
}

// final rounds: 8 => 32 bytes hash
// final rounds: 5 => 20 bytes hash (blake_160)
// msg_len in bytes
pub fn blake3(stack: &mut StackTracker, mut msg_len: u32, final_rounds: u8) -> StackVariable {
    assert!(
        msg_len <= MAX_MSG_SIZE_IMPL,
        "This blake3 implementation supports up to 288 bytes"
    );

    let use_full_tables = msg_len <= 232;

    let num_blocks = (msg_len + 64 - 1) / 64;
    let num_padding_bytes = num_blocks * 64 - msg_len;
    let num_padding_nibbles = num_padding_bytes * 2;

    stack.clear_definitions();
    stack.define(msg_len * 2, "msg");
    stack.to_altstack();

    let tables = tables_for_blake3(stack, use_full_tables);

    let full_msg = stack.from_altstack();
    let mut full_msg = stack.explode(full_msg);

    //process every block
    for i in 0..num_blocks {
        let last_round = i == num_blocks - 1;
        let intermediate_rounds = if last_round { final_rounds } else { 8 };

        let flags = get_flags_for_block(i, num_blocks);

        // add the padding on the last round
        if last_round && num_padding_nibbles > 0 {
            full_msg.push(stack.number(0));
            full_msg.extend(stack.repeat(num_padding_nibbles - 1));
        }

        // create the current block message map
        let mut message = HashMap::new();
        for m in 0..16 {
            let var = full_msg[m * 8 + (16 * 8 * i) as usize];
            stack.join_count(var, 7);
            let le_var = to_le(stack, var);
            message.insert(m as u8, le_var);
        }

        // compress the block
        compress(
            stack,
            i > 0,
            0,
            msg_len.min(64),
            flags,
            message,
            &tables,
            intermediate_rounds,
            last_round,
        );

        if msg_len > 64 {
            msg_len -= 64;
        }

        //drop the rest of the state
        for _ in 0..16 - intermediate_rounds {
            stack.drop_var();
        }
    }

    //drop tables
    tables.drop(stack);

    //get the result hash
    stack.from_altstack_joined(final_rounds as u32 * 8, "blake3-hash")
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    pub use bitcoin_script::{define_pushable, script};
    define_pushable!();
    use bitcoin_script_stack::{
        debugger::debug_script, optimizer::optimize, script_util::verify_n, stack::StackTracker,
    };
    use blake3::Hasher;

    use super::*;

    #[test]
    fn test_rotated_opt() {
        let mut stack = StackTracker::new();
        let tables = tables_for_blake3(&mut stack, true);
        let mut var_map: HashMap<u8, StackVariable> = HashMap::new();

        stack.debug();

        let x = stack.number_u32(0x00112233);
        let y = stack.number_u32(0x99887766);

        var_map.insert(0, x);
        var_map.insert(1, y);

        let ret = right_rotate_xored(&mut stack, &mut var_map, 0, 1, 0, &tables);

        let val = stack.number_u32(0x99995555);
        stack.equals(ret, true, val, true);

        stack.drop(y);
        tables.drop(&mut stack);
        stack.op_true();

        let res = stack.run();
        assert!(res.success);
    }

    #[test]
    fn test_add_and_xor() {
        let mut stack = StackTracker::new();
        let tables = tables_for_blake3(&mut stack, true);

        let x = stack.number_u32(0x00112233);
        let y = stack.number_u32(0x99887766);
        u4_add_direct(&mut stack, 8, vec![y], vec![x], vec![0xaabbccdd], &tables);

        let ret = stack.from_altstack_joined(8, "result");
        let val = stack.number_u32(0x44556676);
        stack.equals(ret, true, val, true);

        stack.drop(y);
        tables.drop(&mut stack);
        stack.op_true();

        let res = stack.run();
        assert!(res.success);
    }

    fn test_blake3_aux(n: u16) {
        let mut stack = StackTracker::new();

        let mut test: Vec<u8> = Vec::new();
        for i in 0..n as u16 {
            test.push((i % 251) as u8);
        }

        let mut hasher = Hasher::new();
        hasher.update(&test);
        let ret = hasher.finalize().as_bytes().to_vec();

        //vec to hex
        let hex_in = test
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();

        let hex_out = ret.iter().map(|x| format!("{:02x}", x)).collect::<String>();

        stack.hexstr_as_nibbles(&hex_in);

        stack.debug();
        let result = blake3(&mut stack, (n * 1) as u32, 8);

        let expected = stack.hexstr_as_nibbles(&hex_out);
        stack.debug();
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_blake3_all() {
        //Reference values used in Blake3 tests
        for i in [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            63,
            64,
            65,
            127,
            128,
            129,
            255,
            MAX_MSG_SIZE_IMPL,
        ] {
            test_blake3_aux(i as u16);
        }
    }

    #[test]
    fn test_blake3() {
        let hex_out = "86ca95aefdee3d969af9bcc78b48a5c1115be5d66cafc2fc106bbd982d820e70";

        let mut stack = StackTracker::new();

        let hex_in = "01000000".repeat(16);
        stack.hexstr_as_nibbles(&hex_in);

        let start = stack.get_script().len();
        let optimized_start = optimize(stack.get_script()).len();
        let result = blake3(&mut stack, 64, 8);
        let end = stack.get_script().len();
        println!("Blake3 size: {}", end - start);

        let end = optimize(stack.get_script()).len();
        println!("Blake3 size: {}", end - optimized_start);

        let expected = stack.hexstr_as_nibbles(&hex_out);
        stack.equals(result, true, expected, true);

        stack.op_true();

        stack.debug();

        let optimized = optimize(stack.get_script());
        assert!(debug_script(optimized).0.result().unwrap().success);

        assert!(stack.run().success);
    }

    #[test]
    fn test_blake3_160() {
        let hex_out = "290eef2c4633e64835e2ea6395e9fc3e8bf459a7";

        let mut stack = StackTracker::new();
        let hex_in = "01000000".repeat(10);
        println!("hex_in: {}", hex_in);
        let _ = stack.hexstr_as_nibbles(&hex_in);

        let start = stack.get_script().len();
        //let result = blake3(&mut stack, 58 / 2, 5);
        let result = blake3(&mut stack, 40, 5);
        let end = stack.get_script().len();
        println!("Blake3 size: {}", end - start);
        stack.debug();

        let expected = stack.hexstr_as_nibbles(&hex_out);
        stack.equals(result, true, expected, true);

        stack.op_true();

        assert!(stack.run().success);
    }

    fn test_long_blakes(repeat: u32, hex_out: &str) {
        let mut stack = StackTracker::new();

        let hex_in = "01000000".repeat(repeat as usize);
        stack.hexstr_as_nibbles(&hex_in);

        let start = stack.get_script().len();
        let result = blake3(&mut stack, repeat * 4, 8);
        let end = stack.get_script().len();
        println!("Blake3 size: {} for: {} bytes", end - start, repeat * 4);

        let expected = stack.hexstr_as_nibbles(&hex_out);
        stack.equals(result, true, expected, true);

        stack.op_true();

        //stack.debug();
        assert!(stack.run().success);
    }

    #[test]
    fn test_blake3_long() {
        let hex_out = "9bd93dd19a93d1d3522c6717d77a2e20e11b8627efa5df80c76d727ca7431892";
        test_long_blakes(20, hex_out);

        let hex_out = "08729d0161b725b93e83ce79b06c534ce7684d39e21ad05074b67e0ac89ef44a";
        test_long_blakes(40, hex_out);

        //limit not moving padding
        let hex_out = "f2487b9f736cc30faf28952733c95560dc60e72cc7731b03a9ecfc86665e2e85";
        test_long_blakes(48, hex_out);

        //limit full tables
        let hex_out = "034acb9761990badc714913b9bb6329d96ed91ea01530a55e8fd4c8ffb3aee42";
        test_long_blakes(57, hex_out);

        let hex_out = "a23e7a7e11ff2febf28a205c8dc0ca57ae4eb2d0eb079bb5c6a5bdcdd3e56de1";
        test_long_blakes(60, hex_out);

        //max limit
        let hex_out = "b6c1b3d6b1555e0d20bd5188e4b8b20488c36105fd9c8971ac10dd267e612e4f";
        test_long_blakes(72, hex_out);
    }

    #[test]
    fn test_rrot7() {
        let mut stack = StackTracker::new();
        let tables = tables_for_blake3(&mut stack, true);

        let mut ret = Vec::new();
        ret.push(stack.number_u32(0xdeadbeaf));
        ret.push(stack.number_u32(0x01020304));

        let mut var_map: HashMap<u8, StackVariable> = HashMap::new();
        var_map.insert(0, ret[0]);
        var_map.insert(1, ret[1]);

        right_rotate7_xored(&mut stack, &mut var_map, 0, 1, &tables);

        stack.number_u32(0x57bf5f7b);

        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.drop(ret[1]);

        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_g() {
        let mut stack = StackTracker::new();

        let tables = tables_for_blake3(&mut stack, true);

        let mut ret = Vec::new();
        for i in 0..6 {
            ret.push(stack.number_u32(i));
        }

        let mut var_map: HashMap<u8, StackVariable> = HashMap::new();
        var_map.insert(0, ret[0]);
        var_map.insert(1, ret[1]);
        var_map.insert(2, ret[2]);
        var_map.insert(3, ret[3]);

        let start = stack.get_script().len();
        g(
            &mut stack,
            &mut var_map,
            0,
            1,
            2,
            3,
            ret[4],
            ret[5],
            &tables,
            false,
        );
        let end = stack.get_script().len();
        println!("G size: {}", end - start);

        stack.number_u32(0xc4d46c6c); //b
        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.number_u32(0x6a063602); //c
        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.number_u32(0x6a003600); //d
        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.number_u32(0x0030006a); //a
        stack.custom(script! { {verify_n(8)}}, 2, false, 0, "verify");

        stack.drop(ret[5]);
        stack.drop(ret[4]);
        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_round() {
        let mut stack = StackTracker::new();

        let tables = tables_for_blake3(&mut stack, true);

        let mut var_map: HashMap<u8, StackVariable> = HashMap::new();
        let mut msg_map: HashMap<u8, StackVariable> = HashMap::new();
        for i in 0..16 {
            var_map.insert(i, stack.number_u32(i as u32));
            msg_map.insert(i, stack.number_u32(i as u32));
        }

        let start = stack.get_script().len();
        round(&mut stack, &mut var_map, &msg_map, &tables, false);
        let end = stack.get_script().len();
        println!("Round size: {}", end - start);
    }
}
