use tfhe::integer::{RadixCiphertext, ServerKey};
use std::rc::Rc;
use std::collections::HashMap;

use crate::regex::parser::RegExpr;
use crate::trials::str2::create_trivial_radix;

pub(crate) struct Execution {
    sk: ServerKey,
    cache: HashMap<(RegExpr, usize), RadixCiphertext>,

    ct_ops: usize,
}

impl Execution {
    pub(crate) fn new(sk: ServerKey) -> Self {
        Self {
            sk,
            cache: HashMap::new(),
            ct_ops: 0,
        }
    }

    pub(crate) fn ct_operations_count(&self) -> usize {
        self.ct_ops
    }

    pub(crate) fn ct_eq(&mut self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.ct_ops += 1;
        self.sk.unchecked_eq(a, b)
    }
    pub(crate) fn ct_ge(&mut self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.ct_ops += 1;
        self.sk.unchecked_ge(a, b)
    }
    pub(crate) fn ct_le(&mut self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.ct_ops += 1;
        self.sk.unchecked_le(a, b)
    }
    pub(crate) fn ct_and(&mut self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.ct_ops += 1;
        self.sk.unchecked_bitand(a, b)
    }
    pub(crate) fn ct_or(&mut self, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
        self.ct_ops += 1;
        self.sk.unchecked_bitor(a, b)
    }
    pub(crate) fn ct_not(&mut self, a: &RadixCiphertext) -> RadixCiphertext {
        self.ct_ops += 1;
        self.sk.unchecked_bitxor(a, &self.ct_constant(1))
    }

    pub(crate) fn ct_false(&self) -> RadixCiphertext {
        self.ct_constant(0)
    }
    pub(crate) fn ct_true(&self) -> RadixCiphertext {
        self.ct_constant(1)
    }
    pub(crate) fn ct_constant(&self, c: u8) -> RadixCiphertext {
        create_trivial_radix(&self.sk, c as u64, 2, 4)
    }
}

#[derive(Clone)]
pub(crate) struct DelayedExecution {
    func: Rc<dyn Fn(&mut Execution) -> RadixCiphertext>,
}

impl DelayedExecution {
    pub(crate) fn new(func: Rc<dyn Fn(&mut Execution) -> RadixCiphertext>) -> Self {
        Self { func }
    }

    pub(crate) fn exec(&self, exec: &mut Execution) -> RadixCiphertext {
        (self.func)(exec)
    }
}
