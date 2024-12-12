use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use crate::util::sort;

fn lookup_from_depth(stack: &mut StackTracker, delta: i32) -> StackVariable {
    for i in (0..16).rev() {
        stack.numberi((i+1) * -16 + delta);
    }
    stack.join_in_stack(15, 16, Some("lookup_depth"))
}

fn half_lookup_from_depth(stack: &mut StackTracker, delta: i32) -> StackVariable {
    for i in 0..16 {
        let diff = ((16-i) * (16-i+1))/2 + i;
        let value =  -diff + delta;
        stack.numberi(value);
    }
    stack.join_in_stack(15, 16, Some("half_lookup_depth"))
}

fn lookup(stack: &mut StackTracker) -> StackVariable {
    for i in (0..16).rev() {
        stack.numberi(i * 16 );
    }
    stack.join_in_stack(15, 16, Some("lookup"))
}

fn half_lookup(stack: &mut StackTracker) -> StackVariable {
    let mut parts = Vec::new();
    let mut prev = 0;
    parts.push(0);
    for i in 1..16 {
        prev = 16 + prev - i;
        parts.push(prev);
    }
    let mut parts = parts.iter().rev().map(|x| stack.number(*x)).collect::<Vec<_>>();
    stack.rename(parts[0], "half_lookup");
    stack.join_count(&mut parts[0], 15)
}

#[derive(Debug)]
pub enum Operation {
    //binary
    And,
    Or,
    Xor,
    MulMod,
    MulQuotient,

    //unary
    LShift(u8),
    RShift(u8),
    Modulo(u32),
    Quotient(u32),
}

impl Operation {
    pub fn is_unary(&self) -> bool {
        match self {
            Operation::LShift(_) | Operation::RShift(_) | Operation::Modulo(_) | Operation::Quotient(_) => true,
            _ => false,
        }
    }
}

fn unary_operation_table(stack: &mut StackTracker, op: &Operation) -> StackVariable {
    let max = match op {
        Operation::Quotient(max) |
        Operation::Modulo(max) => *max,
        _ => 16,
    };

    for i in (0..max).rev() {
        let number = match op {
            Operation::LShift(n) => (i << n) & 0xF,
            Operation::RShift(n) => (i >> n) & 0xF,
            Operation::Modulo(_) => i % 16,
            Operation::Quotient(_) => i / 16,
            _ => unreachable!(),
        };
        stack.number(number as u32);

    }

    stack.join_in_stack(max-1, max, Some(&format!("op_{:?}", op)))
}

fn binary_operation_table(stack: &mut StackTracker, op: &Operation, full_table: bool) -> StackVariable {
    for n in (0..16).rev() {
        let x = if full_table { 0 } else { n };
        for i in (x..16).rev() {
            let number = match op {
                Operation::And => i & n,
                Operation::Or => i | n,
                Operation::Xor => i ^ n,
                Operation::MulMod => (i * n) % 16,
                Operation::MulQuotient => (i * n) / 16,
                _ => unreachable!(),

            };
            //println!("n: {}, i: {}, number: {}", n, i, number);
            stack.number(number);
        }
    }
    let total_size = if full_table { 256 } else { 136 };
    stack.join_in_stack(total_size-1, total_size, Some(&format!("op_{:?}", op)))
}

#[derive(Clone, Debug)]
pub struct StackVariableOp {
    pub var: StackVariable,
    pub n: Option<u32>,
    pub copy: bool,
    pub constant: Option<u32>,
}

impl StackVariableOp {
    pub fn new(var: StackVariable, n: Option<u32>, copy: bool, constant: Option<u32>) -> Self {
        Self {
            var,
            n,
            copy,
            constant,
        }
    }

    pub fn access(&self, stack: &mut StackTracker) -> StackVariable {
        apply_op(stack, Some(self.clone()))
    }

}

fn apply_op(stack: &mut StackTracker, op: Option<StackVariableOp>) -> StackVariable {
    if let Some(var) = op {
        if let Some(c) = var.constant {
            if let Some(n) = var.n {
                stack.number((c >> (4 * (7-n))) & 0xf)
            } else {
                stack.number_u32(c)
            }
        } else {
            if let Some(n) = var.n {
                if var.copy {
                    stack.copy_var_sub_n(var.var, n)
                } else {
                    stack.move_var_sub_n(&mut var.var.clone(), n)
                }
            } else {
                if var.copy {
                    stack.copy_var(var.var)
                } else {
                    stack.move_var(var.var)
                }
            }
        }
    } else {
        StackVariable::null()
    }
}




#[derive(Debug, Default)]
pub struct StackTables {
    pub depth: StackVariable,
    pub depth_is_full_table: bool,

    pub and: StackVariable,
    pub or: StackVariable,
    pub xor: StackVariable,
    pub mul_mod: StackVariable,
    pub mul_quotient: StackVariable,
    pub modulo: StackVariable,
    pub quotient: StackVariable,

    pub lshift: [StackVariable; 5],
    pub rshift: [StackVariable; 5],

    pub lookup: StackVariable,
    pub lookup_is_full_table: bool,
}

impl StackTables {

    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn depth_lookup(mut self, stack: &mut StackTracker, full_table: bool) -> Self {
        //TODO: FIX -17 for blake  -18 for sha for full lookup
        self.depth = if full_table { lookup_from_depth(stack, -18) } else { half_lookup_from_depth(stack, -17) };
        self.depth_is_full_table = full_table;
        self
    }

    pub fn lookup(mut self, stack: &mut StackTracker, full_table: bool) -> Self {
        self.lookup = if full_table { lookup(stack) } else { half_lookup(stack) };
        self.lookup_is_full_table = full_table;
        self
    }

    pub fn operation(mut self, stack: &mut StackTracker, op: &Operation, full_table: bool) -> Self {
        match op {
            &Operation::And => self.and = binary_operation_table(stack, op, full_table),
            &Operation::Or => self.or = binary_operation_table(stack, op, full_table),
            &Operation::Xor => self.xor = binary_operation_table(stack, op, full_table),
            &Operation::MulMod => self.mul_mod = binary_operation_table(stack, op, full_table),
            &Operation::MulQuotient => self.mul_quotient = binary_operation_table(stack, op, full_table),
            &Operation::Modulo(_) => self.modulo = unary_operation_table(stack, op),
            &Operation::Quotient(_) => self.quotient = unary_operation_table(stack, op),
            &Operation::LShift(n) => self.lshift[n as usize] = unary_operation_table(stack, op),
            &Operation::RShift(n) => self.rshift[n as usize] = unary_operation_table(stack, op),
        }
        self
    }

    pub fn rot_operation(self, stack: &mut StackTracker, n: u8, right: bool) -> Self {
        assert!(n < 5);
        let npos = n;
        let ncomplement = 4-n;
        let nright = if right { npos } else { ncomplement };
        let nleft = if right { ncomplement } else { npos };
        self.operation(stack, &Operation::RShift(nright), false)
            .operation(stack, &Operation::LShift(nleft), false)
    }

    pub fn addition_operation(self, stack: &mut StackTracker, n: u32) -> Self {
        self.operation(stack, &Operation::Modulo(n), false)
            .operation(stack, &Operation::Quotient(n), false)
    }

    pub fn get_operation_table(&self, op: &Operation) -> &StackVariable {
        match op {
            &Operation::And => &self.and,
            &Operation::Or => &self.or,
            &Operation::Xor => &self.xor,
            &Operation::MulMod => &self.mul_mod,
            &Operation::MulQuotient => &self.mul_quotient,
            &Operation::Modulo(_) => &self.modulo,
            &Operation::Quotient(_) => &self.quotient,
            &Operation::LShift(n) => &self.lshift[n as usize],
            &Operation::RShift(n) => &self.rshift[n as usize],
        }
    }
   
    pub fn apply(&self, stack: &mut StackTracker, op: &Operation) -> StackVariable {
        let is_binary = !op.is_unary();

        if is_binary && !self.lookup_is_full_table {
            sort(stack);
            println!("sorting");
        }
        if is_binary {
            stack.get_value_from_table(self.lookup, None);
            stack.op_add();
        }
        stack.get_value_from_table(*self.get_operation_table(&op), None);
        stack.get_var_from_stack(1)
    }


    fn apply_with_depth_half(&self, stack: &mut StackTracker, mut x: &mut StackVariable, y: StackVariable, nx: u8, ny: u8 )  -> StackVariable {

        //save two copies of the depth
        stack.op_depth();
        stack.op_dup();

        stack.copy_var_sub_n(y, ny as u32);
        stack.move_var_sub_n(&mut x, nx as u32);

        //save the max to altstack
        //get the min
        stack.op_2dup();
        stack.op_max();
        stack.to_altstack();
        stack.op_min();

        //substract from depth the first value and 1 extra
        stack.op_sub();
        stack.op_1sub();

        //pick the value from the depth lookup table
        //the value is negative so it's added to the depth
        stack.op_pick();
        stack.op_add();
        
        //add the second number to index inside the table
        stack.from_altstack();
        stack.op_add();
        let ret = stack.op_pick();
        ret
    }

    //assumes that x[nx] will be consumed and y[ny] will be copied
    //it also asumes that the depth lookup table is on the botom of the stack followed by the binary operation table
    pub fn apply_with_depth(&self, stack: &mut StackTracker, mut x: &mut StackVariable, y: StackVariable, nx: u8, ny: u8 )  -> StackVariable {

        if !self.depth_is_full_table {
            return self.apply_with_depth_half(stack, x, y, nx, ny);
        }

        stack.op_depth();
        stack.op_dup();

        stack.copy_var_sub_n(y, ny as u32);

        stack.op_sub();
        stack.op_pick();

        stack.op_add();

        stack.move_var_sub_n(&mut x, nx as u32);

        stack.op_add();
        stack.op_pick()
    }

    //it consumes the two nibbles from the top of the stack 
    pub fn apply_with_depth_stack(&self, stack: &mut StackTracker )  -> StackVariable {

        stack.op_depth();
        stack.op_dup();

        //stack.debug();

        stack.op_rot();

        //stack.debug();

        stack.op_sub();
        stack.op_1sub();
        stack.op_pick();

        //stack.debug();

        stack.op_add();
        //stack.debug();
        stack.op_add();
        //stack.debug();
        stack.op_pick()
    }


    //assume that if we want to shift two nibbles, the stack will have the two nibbles on the top of the stack
    //to the top will be applied the shift and to the second from the top will be applied the complement
    //then the result is added
    pub fn apply_shift_two_nibbles(&self, stack: &mut StackTracker, n:u8, right: bool, var_op: Option<StackVariableOp>) -> StackVariable {
        let npos = n;
        let ncomplement = 4-n;
        let op = if right { Operation::RShift(npos) } else { Operation::RShift(ncomplement) };
        let opcomplement = if right { Operation::LShift(ncomplement) } else { Operation::LShift(npos) };

        stack.get_value_from_table(*self.get_operation_table(&op), None);
        if var_op.is_some() {
            apply_op(stack, var_op);
        } else {
            stack.op_swap();
        }
        stack.get_value_from_table(*self.get_operation_table(&opcomplement), None);
        let ret = stack.op_add();
        stack.rename(ret, &format!("shift_two_nibbles_{}", n));
        ret
    }



    pub fn drop(self, stack: &mut StackTracker) {
        let mut tables = vec![
            self.depth,
            self.and,
            self.or,
            self.xor,
            self.mul_mod,
            self.mul_quotient,
            self.modulo,
            self.quotient,
            self.lookup,
        ];
        for i in 0..5 {
            tables.push(self.lshift[i]);
            tables.push(self.rshift[i]);
        }
        tables.retain( |x| !x.is_null());

        stack.drop_list(tables);
    }

}


#[cfg(test)]
mod test {

    use super::*;

    fn test_unary(x:u32, op:Operation, expected:u32) {
        let mut stack = StackTracker::new();
        let tables = StackTables::new().operation(&mut stack, &op, false);

        stack.number(x);
        tables.apply(&mut stack, &op);

        stack.number(expected);
        stack.op_equalverify();
        tables.drop(&mut stack);
        stack.op_true();

        assert!(stack.run().success);
    }

    fn test_binary(x:u32, y:u32, op:Operation, expected:u32, full_table:bool, depth_lookup: bool) {
        let mut stack = StackTracker::new();
        let mut tables = StackTables::new();
        if depth_lookup {
            tables = tables.depth_lookup(&mut stack, full_table).operation(&mut stack, &op, full_table);
        } else {
            tables = tables.lookup(&mut stack, full_table).operation(&mut stack, &op, full_table);
        }

        let mut vx = stack.number(x);
        let vy = stack.number(y);

        if depth_lookup {
            tables.apply_with_depth(&mut stack, &mut vx, vy, 0, 0);
        } else {
            tables.apply(&mut stack, &op);
        }

        stack.number(expected);
        stack.op_equalverify();

        if depth_lookup {
            stack.drop(vy);
        }

        tables.drop(&mut stack);
        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_depth_with_stack() {

        let mut stack = StackTracker::new();
        let tables = StackTables::new()
            .depth_lookup(&mut stack, true).operation(&mut stack, &Operation::Xor, true);

        stack.number(1);
        stack.number(2);

        stack.debug();


        tables.apply_with_depth_stack(&mut stack);

        stack.debug();
        stack.number(3);
        stack.op_equalverify();


        tables.drop(&mut stack);
        stack.op_true();

        assert!(stack.run().success);

    }

    #[test]
    fn test_binary_ops() {
        for depth in [true,false] {
            for b in [false,true] {
                for i in 0..16 {
                    for j in 0..16 {
                        test_binary(i, j, Operation::And, i & j, b, depth);
                        test_binary(i, j, Operation::Or, i | j, b, depth);
                        test_binary(i, j, Operation::Xor, i ^ j, b, depth);
                        test_binary(i, j, Operation::MulMod, (i * j) % 16, b, depth);
                        test_binary(i, j, Operation::MulQuotient, (i * j) / 16,b, depth);
                    }
                }
            }
        }
    }


    #[test]
    fn test_unary_ops() {
        for i in 0..16 {
            for j in 0..5 {
                test_unary(i, Operation::LShift(j), (i << j) & 0xf);
                test_unary(i, Operation::RShift(j), (i >> j) & 0xf);
            }
        }
        for i in 0..32 {
            test_unary(i, Operation::Modulo(32), i % 16);
            test_unary(i, Operation::Quotient(32), i / 16);
        }
    }

    #[test]
    fn test_shift_two_nibbles() {
        for right in [true, false] {
            for x in 0..16 {
                for y in 0..16 {
                    for j in 0..5 {
                        let mut stack = StackTracker::new();
                        let tables = StackTables::new().rot_operation(&mut stack, j, right);

                        let varx = stack.number(x);
                        stack.number(y);
                        let var_op = StackVariableOp::new(varx, None, false, None);
                        tables.apply_shift_two_nibbles(&mut stack, j, right, Some(var_op));

                        let result = x * 16 + y;
                        let result = if right {
                            (result >> j) & 0xf
                        } else {
                            ((result << j) & 0xf0 ) >> 4
                        };
                        stack.number(result); 

                        stack.op_equal();
                        stack.to_altstack();
                        tables.drop(&mut stack);
                        stack.from_altstack();
                        assert!(stack.run().success);
                    }
                }
            }
        }
    }
}