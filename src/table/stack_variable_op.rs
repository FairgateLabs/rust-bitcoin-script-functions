use bitcoin_script_stack::stack::{StackTracker, StackVariable};

#[derive(Clone, Debug)]
pub struct StackVariableOp {
    pub var: StackVariable,
    pub n: Option<u32>,
    pub copy: bool,
    pub constant: Option<u32>,
}

impl Into<StackVariableOp> for StackVariable {
    fn into(self) -> StackVariableOp {
        StackVariableOp::new_var(self)
    }
}

impl Into<StackVariableOp> for u32 {
    fn into(self) -> StackVariableOp {
        StackVariableOp::new_constant(self)
    }
}

impl Into<StackVariable> for StackVariableOp {
    fn into(self) -> StackVariable {
        self.var
    }
}

impl StackVariableOp {
    pub fn new_constant(constant: u32) -> Self {
        Self {
            var: StackVariable::null(),
            n: None,
            copy: true,
            constant: Some(constant),
        }
    }

    pub fn new_var(var: StackVariable) -> Self {
        Self {
            var,
            n: None,
            copy: true,
            constant: None,
        }
    }

    pub fn new(var: StackVariable, n: Option<u32>, copy: bool) -> Self {
        Self {
            var,
            n,
            copy,
            constant: None,
        }
    }

    pub fn null() -> Self {
        Self::new_var(StackVariable::null())
    }

    pub fn set_move(mut self) -> Self {
        self.copy = false;
        self
    }

    pub fn set_n(mut self, n: u32) -> Self {
        self.n = Some(n);
        self
    }

    pub fn read_n(&mut self, stack: &mut StackTracker, n: u32) -> StackVariable {
        self.n = Some(n);
        self.copy = true;
        self.access(stack)
    }

    pub fn move_n(&mut self, stack: &mut StackTracker, n: u32) -> StackVariable {
        self.n = Some(n);
        self.copy = false;
        self.access(stack)
    }

    pub fn access(&self, stack: &mut StackTracker) -> StackVariable {
        apply_op(stack, Some(self.clone()))
    }
}

fn apply_op(stack: &mut StackTracker, op: Option<StackVariableOp>) -> StackVariable {
    if let Some(var) = op {
        if let Some(c) = var.constant {
            if let Some(n) = var.n {
                stack.number((c >> (4 * (7 - n))) & 0xf)
            } else {
                stack.number_u32(c)
            }
        } else {
            if let Some(n) = var.n {
                if var.copy {
                    stack.copy_var_sub_n(var.var, n)
                } else {
                    stack.move_var_sub_n(var.var, n)
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
