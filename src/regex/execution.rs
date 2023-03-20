use tfhe::integer::{RadixCiphertext, ServerKey};
use std::rc::Rc;
use std::collections::HashMap;

use crate::regex::parser::RegExpr;
use crate::trials::str2::create_trivial_radix;

pub(crate) struct Execution {
    sk: ServerKey,
    cache: HashMap<(RegExpr, usize), RadixCiphertext>,

    ct_ops: usize,
    cache_hits: usize,
}
pub(crate)type LazyExecution = Rc<dyn Fn(&mut Execution) -> RadixCiphertext>;

pub(crate) fn lazy_exec_cached(ctx: (RegExpr, usize), func: LazyExecution) -> LazyExecution  {
    Rc::new(move |exec| {
        exec.with_cache(ctx.clone(), func.clone())
    })
}

impl Execution {
    pub(crate) fn new(sk: ServerKey) -> Self {
        Self {
            sk,
            cache: HashMap::new(),
            ct_ops: 0,
            cache_hits: 0,
        }
    }

    pub(crate) fn ct_operations_count(&self) -> usize {
        self.ct_ops
    }

    pub(crate) fn cache_hits(&self) -> usize {
        self.cache_hits
    }

    pub(crate) fn with_cache(&mut self, ctx: (RegExpr, usize), f: LazyExecution) -> RadixCiphertext {
        if let Some(res) = self.cache.get(&ctx) {
            self.cache_hits += 1;
            return res.clone();
        }
        info!("evaluation at {:?}: {:?}", &ctx.1, &ctx.0);
        let res = f(self);
        self.cache.insert(ctx, res.clone());
        res
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
