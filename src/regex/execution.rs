use std::collections::HashMap;
use std::rc::Rc;
use tfhe::integer::{RadixCiphertext, ServerKey};

use crate::regex::parser::u8_to_char;
use crate::trials::str2::create_trivial_radix;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) enum Executed {
    Constant { c: u8 },
    CtPos { at: usize },
    And { a: Box<Executed>, b: Box<Executed> },
    Or { a: Box<Executed>, b: Box<Executed> },
    Equal { a: Box<Executed>, b: Box<Executed> },
    GreaterOrEqual { a: Box<Executed>, b: Box<Executed> },
    LessOrEqual { a: Box<Executed>, b: Box<Executed> },
    Not { a: Box<Executed> },
}
type ExecutedResult = (RadixCiphertext, Executed);

impl Executed {
    pub(crate) fn ct_pos(at: usize) -> Self {
        Executed::CtPos { at }
    }
}

pub(crate) struct Execution {
    sk: ServerKey,
    cache: HashMap<Executed, RadixCiphertext>,

    ct_ops: usize,
    cache_hits: usize,
}
pub(crate) type LazyExecution = Rc<dyn Fn(&mut Execution) -> ExecutedResult>;

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

    pub(crate) fn ct_eq(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::Equal {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec: &mut Execution| {
                exec.ct_ops += 1;

                (exec.sk.unchecked_eq(&a.0, &b.0), ctx.clone())
            }),
        )
    }

    pub(crate) fn ct_ge(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::GreaterOrEqual {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                (exec.sk.unchecked_ge(&a.0, &b.0), ctx.clone())
            }),
        )
    }

    pub(crate) fn ct_le(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::LessOrEqual {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                (exec.sk.unchecked_le(&a.0, &b.0), ctx.clone())
            }),
        )
    }

    pub(crate) fn ct_and(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::And {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                (exec.sk.unchecked_bitand(&a.0, &b.0), ctx.clone())
            }),
        )
    }

    pub(crate) fn ct_or(&mut self, a: ExecutedResult, b: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::Or {
            a: Box::new(a.1.clone()),
            b: Box::new(b.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                (exec.sk.unchecked_bitor(&a.0, &b.0), ctx.clone())
            }),
        )
    }

    pub(crate) fn ct_not(&mut self, a: ExecutedResult) -> ExecutedResult {
        let ctx = Executed::Not {
            a: Box::new(a.1.clone()),
        };
        self.with_cache(
            ctx.clone(),
            Rc::new(move |exec| {
                exec.ct_ops += 1;

                (
                    exec.sk.unchecked_bitxor(&a.0, &exec.ct_constant(1).0),
                    ctx.clone(),
                )
            }),
        )
    }

    pub(crate) fn ct_false(&self) -> ExecutedResult {
        self.ct_constant(0)
    }

    pub(crate) fn ct_true(&self) -> ExecutedResult {
        self.ct_constant(1)
    }

    pub(crate) fn ct_constant(&self, c: u8) -> ExecutedResult {
        (
            create_trivial_radix(&self.sk, c as u64, 2, 4),
            Executed::Constant { c },
        )
    }

    fn with_cache(&mut self, ctx: Executed, f: LazyExecution) -> ExecutedResult {
        if let Some(res) = self.cache.get(&ctx) {
            debug!("cache hit: {:?}", &ctx);
            self.cache_hits += 1;
            return (res.clone(), ctx);
        }
        info!("evaluation for: {:?}", &ctx);
        let res = f(self);
        self.cache.insert(ctx, res.0.clone());
        res
    }
}

impl std::fmt::Debug for Executed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Constant { c } => match c {
                0 => write!(f, "f"),
                1 => write!(f, "t"),
                _ => write!(f, "{}", u8_to_char(*c)),
            },
            Self::CtPos { at } => write!(f, "ct_{}", at),
            Self::And { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, "/\\")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::Or { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, "\\/")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::Equal { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, "==")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::GreaterOrEqual { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, ">=")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::LessOrEqual { a, b } => {
                write!(f, "(")?;
                a.fmt(f)?;
                write!(f, "<=")?;
                b.fmt(f)?;
                write!(f, ")")
            }
            Self::Not { a } => {
                write!(f, "(!")?;
                a.fmt(f)?;
                write!(f, ")")
            }
        }
    }
}
