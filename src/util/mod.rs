use bitcoin_script_stack::stack::StackTracker;

pub fn sort(stack: &mut StackTracker) {
    stack.op_2dup();
    stack.op_min();
    stack.to_altstack();
    stack.op_max();
    stack.from_altstack();
}
