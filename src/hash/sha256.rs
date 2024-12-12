use std::{collections::HashMap, mem::swap};

use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use crate::table::stack_tables::{Operation, StackTables, StackVariableOp};



const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITSTATE_MAPPING : [char; 8] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];

const INITSTATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn tables_for_sha256(stack: &mut StackTracker) -> StackTables {
    let tables = StackTables::new()
        .depth_lookup(stack, true)
        .operation(stack, &Operation::Xor, true)
        .rot_operation(stack, 1, true)
        .rot_operation(stack, 2, true)
        .rot_operation(stack, 3, true)
        .operation(stack, &Operation::And, true)
        //.operation(stack, &Operation::Xor, true)
        .lookup(stack, true)
        .addition_operation(stack, 49);

    tables
}

pub fn rrot_nib_from_u32(stack: &mut StackTracker, tables: &StackTables, number: StackVariable, nib: u32, shift: u32, is_shift: bool) -> StackVariable {
    let pos_shift = shift / 4;

    if pos_shift > nib && is_shift {
        return stack.number(0);
    }

    let y = (8 - pos_shift + nib - 1) % 8;
    let x = (8 - pos_shift + nib ) % 8;

    if y == 7 && is_shift {
        stack.copy_var_sub_n(number, y);
    }

    let bit_shift = (shift % 4) as u8;

    if y == 7 && is_shift {
        tables.apply(stack, &Operation::RShift(bit_shift))
    } else {
        stack.copy_var_sub_n(number, x);
        tables.apply_shift_two_nibbles(stack, bit_shift, true, Some(StackVariableOp::new(number, Some(y), true, None)))
    }

}

pub fn calculate_s_stack_nib(  stack: &mut StackTracker, 
                          number: StackVariable, 
                          tables: &StackTables,
                     shift_value: &Vec<u32>, 
                   last_is_shift: bool,
                             nib: u32 ) -> StackVariable 
{
    rrot_nib_from_u32(stack, tables, number, nib, shift_value[0], false);
    rrot_nib_from_u32(stack, tables, number, nib, shift_value[1], false);
    tables.apply_with_depth_stack(stack);
    rrot_nib_from_u32(stack, tables, number, nib, shift_value[2], last_is_shift);
    tables.apply_with_depth_stack(stack)
}


pub fn rrot(number: u32, shift: u32, last_is_shift: bool) -> u32 {
    let orpart = if last_is_shift { 0 } else { number << (32 - shift) };
    (number >> shift) | orpart 
}

pub fn calculate_s_nib_off( number: u32,
                     shift_value: &Vec<u32>, 
                   last_is_shift: bool ,
                             nib: u32) -> u32 
{
    let a = rrot(number, shift_value[0], last_is_shift);
    let b = rrot(number, shift_value[1], last_is_shift);
    let c = rrot(number, shift_value[2], last_is_shift);
    let ret = a ^ b ^ c;
    (ret >> (4 * (7-nib))) & 0xf
}


pub fn calculate_s_nib_var_op( stack: &mut StackTracker, 
                          tables: &StackTables,
                          number: StackVariableOp,
                     shift_value: &Vec<u32>, 
                   last_is_shift: bool ,
                             nib: u32) -> StackVariable 
{
    if number.var.is_null() {
       stack.number(calculate_s_nib_off(number.constant.unwrap(), shift_value, last_is_shift, nib))
    } else {
       calculate_s_stack_nib(stack, number.var, tables, shift_value, last_is_shift, nib)
    }
}


pub fn ch_calculation_stack_nib(stack: &mut StackTracker, mut e: StackVariableOp, mut f:StackVariableOp, mut g:StackVariableOp, tables: &StackTables, nib: u32) -> StackVariable {

    e.n = Some(nib);
    f.n = Some(nib);
    g.n = Some(nib);

    e.access(stack);        // e[nib]
    stack.op_dup();                        // e e

    stack.op_negate();                     // e ~e
    stack.number(15);
    stack.op_add();

    g.access(stack);    // e ~e g[nib]

    tables.apply(stack, &Operation::And); // e ( ~e & g )
    
    stack.op_swap();                       // ( ~e & g ) e

    f.access(stack);   // ( ~e & g ) e f[nib]

    tables.apply(stack, &Operation::And); // ( ~e & g ) (e & f)
    tables.apply_with_depth_stack(stack) // ( ~e & g ) (e & f)
}


pub fn maj_calculation_stack_nib(stack: &mut StackTracker, mut a: StackVariableOp, mut b:StackVariableOp, mut c:StackVariableOp, tables: &StackTables, nib: u32) -> StackVariable {

    a.n = Some(nib);
    b.n = Some(nib);
    c.n = Some(nib);

    a.access(stack);              // a[nib]

    b.access(stack);              // a b[nib]

    stack.op_2dup();                                  // a b a b

    tables.apply_with_depth_stack(stack);           // a b (a^b)

    c.access(stack);                     // a b (a^b) c

    tables.apply(stack, &Operation::And); // a b ((a^b) & c)

    stack.op_rot();
    stack.op_rot();                                  // ((a^b) & c) a b

    tables.apply(stack, &Operation::And); // ((a^b) & c) (a & b)

    tables.apply_with_depth_stack(stack)           // ((a^b) & c) ^ (a & b)

}

pub fn get_w(stack: &mut StackTracker, r: u32, nib: u32, msg_map: &HashMap<u32, StackVariableOp>, tables: &StackTables) -> StackVariable {

    if r < 16 {
        let mut w = msg_map.get(&r).cloned().unwrap();
        w.n = Some(nib);
        return w.access(stack);
    }

    let w_sub_15 = msg_map.get(&(r - 15)).cloned().unwrap();
    let w_sub_2 = msg_map.get(&(r - 2)).cloned().unwrap();
    let _s0 = calculate_s_nib_var_op(stack, &tables, w_sub_15, &vec![7,18,3], true, nib);
    let _s1 = calculate_s_nib_var_op(stack, &tables, w_sub_2, &vec![17,19,10], true, nib);
    stack.op_add();   //s0 + s1


    //this is the last time w[ r - 16 ] is used
    let mut w_sub_16 = msg_map.get(&(r - 16)).cloned().unwrap();
    w_sub_16.n = Some(nib);
    w_sub_16.copy = false;
    
    let mut w_sub_7 = msg_map.get(&(r - 7)).cloned().unwrap();
    w_sub_7.n = Some(nib);

    w_sub_16.access(stack);
    stack.op_add();
    w_sub_7.access(stack);
    stack.op_add()


}


pub fn round(stack: &mut StackTracker, r: u32, var_map: &mut HashMap<char, StackVariableOp>, msg_map: &mut HashMap<u32, StackVariableOp>, tables: &StackTables) {


    for nib in (0..8).rev() {

        let a = var_map.get(&'a').cloned().unwrap();
        let b = var_map.get(&'b').cloned().unwrap();
        let c = var_map.get(&'c').cloned().unwrap();
        let mut d = var_map.get(&'d').cloned().unwrap();
        let e = var_map.get(&'e').cloned().unwrap();
        let f = var_map.get(&'f').cloned().unwrap();
        let g = var_map.get(&'g').cloned().unwrap();
        let mut h = var_map.get(&'h').cloned().unwrap();
        let _s0 = calculate_s_nib_var_op(stack, &tables, a.clone(), &vec![2,13,22], false, nib);
        let _maj = maj_calculation_stack_nib(stack, a, b, c, &tables, nib);
        //stack.debug();
        stack.op_add(); //s0 + maj


        let _s1 = calculate_s_nib_var_op(stack, &tables, e.clone(), &vec![6,11,25], false, nib);
        let _ch = ch_calculation_stack_nib(stack, e, f, g, &tables, nib);
        h.n = Some(nib);
        h.access(stack);
        StackVariableOp::new(StackVariable::null(),Some(nib), false, Some(K[r as usize])).access(stack);

        stack.op_add(); //s1 + ch
        stack.op_add(); // s1 + ch + h[nib]
        stack.op_add(); // s1 + ch + h[hib] + k[r][nib]

        get_w(stack, r, nib, msg_map, tables);
        stack.op_add(); // s1 + ch + h[hib] + k[r][nib] + w[r][nib]  = temp1

        stack.op_dup(); // temp2 temp1 temp1
        stack.op_rot(); // temp1 temp1 temp2
        stack.op_add(); // temp1 a[nib] = temp1 + temp2

        if nib < 7 {
            stack.from_altstack();
            stack.op_add();
        }

        get_quot_and_modulo(stack, tables, nib != 0);
        if nib != 0 {
            stack.to_altstack();
        } 

        d.n = Some(nib);    //temp1 d[nib]  | a[nib]
        d.access(stack);    
        stack.op_add();     //e[nib]       | a[nib]

        if nib < 7 {
            stack.op_rot();
            stack.op_add();
        }

        get_quot_and_modulo(stack, tables, nib != 0);
        stack.from_altstack();

    }

    //drop old vars
    let a = var_map.get(&'a').cloned().unwrap();
    if !a.var.is_null() {
        stack.move_var(a.var);
        stack.drop(a.var);
    }
    let e = var_map.get(&'e').cloned().unwrap();
    if !e.var.is_null() {
        stack.move_var(e.var);
        stack.drop(e.var);
    }

    let e = stack.join_in_stack(7, 8, Some("e"));
    stack.reverse_u32(e);


    let a = stack.from_altstack_joined(8, "a");

    var_map.insert('h', var_map[&'g'].clone());
    var_map.insert('g', var_map[&'f'].clone());
    var_map.insert('f', var_map[&'e'].clone());
    var_map.insert('e', StackVariableOp::new(e, None, true, None));
    var_map.insert('d', var_map[&'c'].clone());
    var_map.insert('c', var_map[&'b'].clone());
    var_map.insert('b', var_map[&'a'].clone());
    var_map.insert('a', StackVariableOp::new(a, None, true, None));

    println!("{:?}", var_map);  


    stack.debug();
}



pub fn sha256(stack: &mut StackTracker, msg_len: u32 ) -> StackVariable {

    for _ in 0..msg_len * 2 {
        stack.to_altstack();
    }

    stack.clear_definitions();

    let tables = tables_for_sha256(stack);

    //for _ in 0..msg_len * 2 {
    //    stack.from_altstack();
    //}
    //TODO: calculate proper message values
    //TODO: generate padding with constants
    //TODO: support more chunks

    let mut msg_map : HashMap<u32, StackVariableOp> = HashMap::new();
    msg_map.insert(0, StackVariableOp::new(stack.from_altstack_joined(8, "w0"), None, true, None));  
    msg_map.insert(1, StackVariableOp::new(stack.from_altstack_joined(8, "w1"), None, true, None));  


    let mut var_map : HashMap<char, StackVariableOp> = HashMap::new();
    for i in 0..8 {
        var_map.insert(INITSTATE_MAPPING[i],  StackVariableOp::new(StackVariable::null(), None, false, Some(INITSTATE[i])) );
    }


    stack.debug();
    for i in 0..64 {
        round(stack, i, &mut var_map, &mut msg_map, &tables);
        if i == 1 {
            return StackVariable::null();
        }

    }
   

    StackVariable::null()
}


pub fn quot_and_modulo_big(stack: &mut StackTracker, number: u32, quot: u32, quotient: bool) {

    stack.op_dup();
    stack.number(number);
    stack.op_greaterthanorequal();
    let (mut if_true, mut if_false) =  stack.open_if();
    if_true.number(number);
    if_true.op_sub();   //a - number
    if quotient {
        if_true.number(quot);
        if_false.number(0);
        stack.end_if(if_true, if_false, 0, vec![(1,"quotient".to_string())], 0);
    } else {
        stack.end_if(if_true, if_false, 0, vec![], 0);
    }
}


pub fn get_quot_and_modulo(stack: &mut StackTracker, tables: &StackTables, quotient: bool) {

    quot_and_modulo_big(stack, 0x60, 6, quotient);

    if quotient {
        stack.op_swap(); 
    }   

    quot_and_modulo_big(stack, 0x30, 3, quotient);

    if quotient {
        stack.op_swap();   
        stack.op_dup();
    }

    tables.apply(stack, &Operation::Modulo(0));
    
    stack.to_altstack();

    if quotient {
        tables.apply(stack, &Operation::Quotient(0));
        stack.op_add();
        stack.op_add();
    }


}




#[cfg(test)]
mod tests {
    use bitcoin_script_stack::stack::StackTracker;
    use sha2::{Sha256, Digest};

    use crate::hash::sha256::sha256;

    use super::*;

    #[test]
    fn test_add_big() {
        for quotient in [false, true ] {
            for n in 0..160 {
                let mut stack = StackTracker::new();
                let tables = tables_for_sha256(&mut stack);

                stack.number(n);

                let start = stack.get_script().len();
                get_quot_and_modulo(&mut stack, &tables, quotient);
                let end = stack.get_script().len();
                println!("len: {}", end - start);

                if quotient {
                    stack.number(n >> 4);
                    stack.op_equalverify();
                }

                stack.number(n & 0xf);
                stack.from_altstack();
                stack.op_equalverify();

                tables.drop(&mut stack);
                stack.op_true();
                assert!(stack.run().success);
            }
        }

    }

    #[test]
    fn test_sha256() {

        let msg = "48656c6c6f20776f";
        //let msg = "deadbeef";
        let expected = get_sha(msg);
        println!("{}", expected);

        let mut stack = StackTracker::new();
        let big_msg = stack.hexstr_as_nibbles(&msg);
        stack.explode(big_msg);
        stack.debug();

        let start = stack.get_script().len();
        let result = sha256(&mut stack, msg.len() as u32 / 2);

        let end = stack.get_script().len();
        println!("len: {}", end - start);

    }
   

    #[test]
    fn test_s_off() {
        let expected = [3,5,8,7,2,7,2,0xb];
        for i in 0..8 {
            let number = INITSTATE[4];
            let shift = vec![6,11,25];
            let last_is_shift = false;
            let res = calculate_s_nib_off(number, &shift, last_is_shift, i);
            assert_eq!(res, expected[i as usize]);
            println!("{}: {:x}", i, res);
        }
    }

    fn calculate_s_stack(  stack: &mut StackTracker, 
                            number: StackVariable, 
                            tables: &StackTables,
                        shift_value: &Vec<u32>, 
                    last_is_shift: bool ) -> StackVariable 
    {
        for nib in 0..8 {
            calculate_s_stack_nib(stack, number, tables, shift_value, last_is_shift, nib);
        }
        stack.join_in_stack(7, 8, Some("s"))
    }

    #[test]
    fn test_s() {
        let mut stack = StackTracker::new();
        let tables = tables_for_sha256(&mut stack);
        let number = stack.number_u32(INITSTATE[4]);
        let mut x = stack.number(1);
        stack.repeat(200);
        stack.join_count(&mut x, 200);
        
        let start = stack.get_script().len();
        let mut ret = calculate_s_stack(&mut stack, number, &tables, &vec![6,11,25], false);
        stack.debug();
        let end = stack.get_script().len();
        let mut expected = stack.number_u32(0x3587272b);
        stack.equals(&mut ret, true, &mut expected, true);

        stack.drop(x);
        stack.drop(number);

        tables.drop(&mut stack);
        stack.op_true();

        println!("len: {}", end - start);   
        assert!(stack.run().success);

    }

    fn ch_calculation_stack(stack: &mut StackTracker, e: StackVariable, f:StackVariable, g:StackVariable, tables: &StackTables) -> StackVariable {
        for nib in 0..8 {
            let ope = StackVariableOp::new(e, Some(nib), true, None);
            let opf = StackVariableOp::new(f, Some(nib), true, None);
            let opg = StackVariableOp::new(g, Some(nib), true, None);

            ch_calculation_stack_nib(stack, ope, opf, opg, tables, nib);
        }
        stack.join_in_stack(7, 8, Some("ch"))

    }

    #[test]
    fn test_ch() {
        let mut stack = StackTracker::new();
        let tables = tables_for_sha256(&mut stack);
        let e  = stack.number_u32(INITSTATE[4]);
        let f  = stack.number_u32(INITSTATE[5]);
        let g  = stack.number_u32(INITSTATE[6]);
        let mut x = stack.number(1);
        stack.repeat(200);
        stack.join_count(&mut x, 200);
        
        let start = stack.get_script().len();
        let mut ret = ch_calculation_stack(&mut stack, e,f,g, &tables);
        stack.debug();
        let end = stack.get_script().len();
        let mut expected = stack.number_u32(0x1f85c98c);
        stack.equals(&mut ret, true, &mut expected, true);

        stack.drop(x);
        stack.drop(g);
        stack.drop(f);
        stack.drop(e);

        tables.drop(&mut stack);
        stack.op_true();

        println!("len: {}", end - start);   
        assert!(stack.run().success);

    }

    fn maj_calculation_stack(stack: &mut StackTracker, a: StackVariable, b:StackVariable, c:StackVariable, tables: &StackTables) -> StackVariable {

        for nib in 0..8 {
            let opa = StackVariableOp::new(a, Some(nib), true, None);
            let opb = StackVariableOp::new(b, Some(nib), true, None);
            let opc = StackVariableOp::new(c, Some(nib), true, None);
            maj_calculation_stack_nib(stack, opa, opb, opc, tables, nib);
        }
        stack.join_in_stack(7, 8, Some("maj"))

    }

    #[test]
    fn test_maj() {
        let mut stack = StackTracker::new();
        let tables = tables_for_sha256(&mut stack);
        let a  = stack.number_u32(INITSTATE[0]);
        let b  = stack.number_u32(INITSTATE[1]);
        let c  = stack.number_u32(INITSTATE[2]);
        let mut x = stack.number(1);
        stack.repeat(200);
        stack.join_count(&mut x, 200);
        
        let start = stack.get_script().len();
        let mut ret = maj_calculation_stack(&mut stack, a,b,c, &tables);
        stack.debug();
        let end = stack.get_script().len();
        let mut expected = stack.number_u32(0x3a6fe667);
        stack.equals(&mut ret, true, &mut expected, true);

        stack.drop(x);
        stack.drop(c);
        stack.drop(b);
        stack.drop(a);

        tables.drop(&mut stack);
        stack.op_true();

        println!("len: {}", end - start);   
        assert!(stack.run().success);

    }


    fn get_sha(msg:&str) -> String {

        let mut hasher = Sha256::new();
        let data = hex::decode(msg).unwrap();
        hasher.update(&data);

        let result = hasher.finalize();
        let res = hex::encode(result);
        res

    }




}