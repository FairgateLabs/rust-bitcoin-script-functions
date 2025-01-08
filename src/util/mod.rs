use bitcoin_script_stack::stack::StackTracker;

pub fn sort(stack: &mut StackTracker) {
    stack.op_2dup();
    stack.op_min();
    stack.to_altstack();
    stack.op_max();
    stack.from_altstack();
}

pub fn quot_and_modulo_big(stack: &mut StackTracker, number: u32, quot: u32, quotient: bool) {
    stack.op_dup();
    stack.number(number);
    stack.op_greaterthanorequal();
    let (mut if_true, mut if_false) = stack.open_if();
    if_true.number(number);
    if_true.op_sub(); //a - number
    if quotient {
        if_true.number(quot);
        if_false.number(0);
        stack.end_if(if_true, if_false, 0, vec![(1, "quotient".to_string())], 0);
    } else {
        stack.end_if(if_true, if_false, 0, vec![], 0);
    }
}
