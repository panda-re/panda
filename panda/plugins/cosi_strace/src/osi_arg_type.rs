use crate::c_type_parser::Type;
use panda::abi::StorageLocation;
use panda::plugins::cosi::{self, OsiType};
use panda::prelude::*;
use std::io::Write;

#[derive(Clone)]
pub(crate) enum OsiArgType {
    Struct(&'static cosi::VolatilityStruct),
    Enum(&'static cosi::VolatilityEnum),
    Base(&'static cosi::VolatilityBaseType),
    UnsignedBase(&'static cosi::VolatilityBaseType),
    Const(Box<OsiArgType>),
    Ptr(Box<OsiArgType>),
    FixedWidth(IntType),
    CStr,
    VoidPtr,
    Fallback,
}

unsafe impl Sync for OsiArgType {}
unsafe impl Send for OsiArgType {}

impl std::fmt::Debug for OsiArgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsiArgType::Struct(x) => write!(f, "Struct(type={})", x.name()),
            OsiArgType::Enum(x) => write!(f, "Enum(type={})", x.name()),
            OsiArgType::Base(x) => write!(f, "Base(type={})", x.name()),
            OsiArgType::UnsignedBase(x) => write!(f, "UnsignedBase(type={})", x.name()),
            OsiArgType::Const(x) => write!(f, "Const({:?})", x),
            OsiArgType::Ptr(x) => write!(f, "Ptr({:?})", x),
            OsiArgType::FixedWidth(x) => write!(f, "{:?}", x),
            OsiArgType::CStr => f.write_str("CStr"),
            OsiArgType::VoidPtr => f.write_str("VoidPtr"),
            OsiArgType::Fallback => f.write_str("Fallback"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum IntType {
    U32,
    U64,
    I32,
    I64,
}

impl OsiArgType {
    pub(crate) fn name(&self) -> String {
        match self {
            OsiArgType::Struct(x) => x.name(),
            OsiArgType::Enum(x) => x.name(),
            OsiArgType::Base(x) => x.name(),
            OsiArgType::UnsignedBase(x) => x.name(),
            OsiArgType::Const(x) => format!("const {}", x.name()),
            OsiArgType::Ptr(x) if matches!(**x, OsiArgType::Fallback) => "pointer".into(),
            OsiArgType::Ptr(x) => format!("{}*", x.name()),
            OsiArgType::FixedWidth(x) => match x {
                IntType::U64 => "u64",
                IntType::U32 => "u32",
                IntType::I64 => "i64",
                IntType::I32 => "i32",
            }
            .to_owned(),
            OsiArgType::CStr => String::from("char*"),
            OsiArgType::VoidPtr => String::from("void*"),
            OsiArgType::Fallback => String::from("[???]"),
        }
    }

    pub(crate) fn ignore_const(&self) -> &Self {
        match self {
            Self::Const(inner) => &*inner,
            _ => self,
        }
    }

    pub(crate) fn is_fallback(&self) -> bool {
        matches!(self.ignore_const(), Self::Fallback)
    }

    pub(crate) fn is_cstr(&self) -> bool {
        matches!(self.ignore_const(), Self::CStr)
    }

    pub(crate) fn is_const(&self) -> bool {
        matches!(self, Self::Const(_)) || matches!(self, Self::Ptr(x) if x.is_const())
    }

    pub(crate) fn make_unsigned(self) -> Self {
        match self {
            Self::Base(inner) => Self::UnsignedBase(inner),
            Self::FixedWidth(IntType::I32) => Self::FixedWidth(IntType::U32),
            Self::FixedWidth(IntType::I64) => Self::FixedWidth(IntType::U64),
            this => this,
        }
    }

    #[allow(unused_must_use)]
    pub(crate) fn read_display<W, RegIter>(&self, cpu: &mut CPUState, f: &mut W, regs: &mut RegIter)
    where
        W: Write,
        RegIter: Iterator<Item = StorageLocation>,
    {
        let reg = regs.next().unwrap();
        let val = reg.read(cpu);
        match self {
            Self::Ptr(inner) => {
                inner.read_display_ptr(cpu, f, val);
            }
            Self::Base(inner) => {
                display_base(val, inner.size(), inner.signed(), f);
            }
            Self::UnsignedBase(inner) => {
                display_base(val, inner.size(), false, f);
            }

            ty if ty.is_const() && ty.ignore_const().is_cstr() => {
                let string = cpu.mem_read_string(val);
                write!(f, "{:?}", string);
            }

            Self::Fallback => {
                write!(f, "{:#x?}", val);
            }

            Self::Struct(ty) => panic!("Struct {:?} in top-level arg?", ty.name()),
            Self::Enum(en) => {
                write!(f, "({}){:#x?}", en.name(), val);
            }
            Self::FixedWidth(ty) => match ty {
                IntType::U32 => display_base(val, 4, false, f),
                IntType::U64 => display_base(val, 8, false, f),
                IntType::I32 => display_base(val, 4, true, f),
                IntType::I64 => display_base(val, 8, true, f),
            },

            Self::VoidPtr => {
                write!(f, "(void*){:#x?}", val);
            }

            Self::Const(ty) => {
                write!(f, "[const {}...]", ty.name());
            }

            Self::CStr => {
                write!(f, "(char*){:#x?}", val);
            }
        }
    }

    #[allow(unused_must_use)]
    pub(crate) fn read_display_ptr<W>(&self, cpu: &mut CPUState, f: &mut W, ptr: target_ptr_t)
    where
        W: Write,
    {
        match self {
            Self::Ptr(inner) => {
                if let Ok(ptr) = target_ptr_t::osi_read(cpu, ptr) {
                    if ptr == 0 {
                        if inner.is_fallback() {
                            write!(f, "NULL");
                        } else {
                            write!(f, "({}*)NULL", inner.name());
                        }
                    } else {
                        inner.read_display_ptr(cpu, f, ptr);
                    }
                } else {
                    write!(f, "({:?}){:#x?}", self.name(), ptr);
                }
            }

            Self::Base(inner) => {
                let is_err = (|| {
                    match (inner.size(), inner.signed()) {
                        (1, false) => write!(f, "{:#x?}", u8::osi_read(cpu, ptr)?),
                        (1, true) => write!(f, "{}", i8::osi_read(cpu, ptr)?),
                        (2, false) => write!(f, "{:#x?}", u16::osi_read(cpu, ptr)?),
                        (2, true) => write!(f, "{}", i16::osi_read(cpu, ptr)?),
                        (4, false) => write!(f, "{:#x?}", u32::osi_read(cpu, ptr)?),
                        (4, true) => write!(f, "{}", i32::osi_read(cpu, ptr)?),
                        (8, false) => write!(f, "{:#x?}", u64::osi_read(cpu, ptr)?),
                        (8, true) => write!(f, "{}", i64::osi_read(cpu, ptr)?),
                        (size, signed) => panic!("Invalid int: size={}, signed={}", size, signed),
                    }
                    .unwrap();

                    Ok::<_, panda::GuestReadFail>(())
                })()
                .is_err();

                if is_err {
                    write!(f, "({}*){:#x?}", inner.name(), ptr);
                }
            }
            Self::UnsignedBase(inner) => {
                let is_err = (|| {
                    match inner.size() {
                        1 => write!(f, "{:#x?}", u8::osi_read(cpu, ptr)?),
                        2 => write!(f, "{:#x?}", u16::osi_read(cpu, ptr)?),
                        4 => write!(f, "{:#x?}", u32::osi_read(cpu, ptr)?),
                        8 => write!(f, "{:#x?}", u64::osi_read(cpu, ptr)?),
                        size => panic!("Invalid int: size={}, signed=false", size),
                    }
                    .unwrap();

                    Ok::<_, panda::GuestReadFail>(())
                })()
                .is_err();

                if is_err {
                    write!(f, "(unsigned {}*){:#x?}", inner.name(), ptr);
                }
            }

            Self::Const(inner) if matches!(&**inner, Self::Struct(_)) => {
                if let Self::Struct(ty) = **inner {
                    write!(f, "{{");
                    let mut first = true;
                    for (name, offset) in ty.fields() {
                        if !first {
                            write!(f, ", ");
                        }

                        let arg_type = ty.type_of(&name);

                        let osi_type = Type::parse(arg_type.trim())
                            .map(OsiArgType::from)
                            .unwrap_or_else(|err| {
                                log::warn!("failed to parse {:?} ({:?})", arg_type, err);
                                OsiArgType::Fallback
                            });

                        if osi_type.is_fallback() {
                            println!("\n\n{:?} failed to parse\n", arg_type);
                        }

                        first = false;
                        write!(f, "{}=", name);
                        osi_type.read_display_ptr(cpu, f, ptr + offset);
                    }
                    write!(f, "}}");
                }
            }

            ty if ty.is_const() && ty.ignore_const().is_cstr() => {
                if let Ok(ptr) = target_ptr_t::osi_read(cpu, ptr) {
                    let string = cpu.mem_read_string(ptr);
                    write!(f, "{:?}", string);
                } else {
                    write!(f, "(char**){:#x?}", ptr);
                }
            }

            Self::Fallback => {
                write!(f, "(pointer){:#x?}", ptr);
            }

            Self::Struct(ty) => {
                write!(f, "({}*){:#x?}", ty.name(), ptr);
            }
            Self::Enum(en) => {
                write!(f, "({}*){:#x?}", en.name(), ptr);
            }
            Self::FixedWidth(ty) => {
                let is_err = (|| {
                    match ty {
                        IntType::U32 => write!(f, "{:#x?}", u32::osi_read(cpu, ptr)?),
                        IntType::U64 => write!(f, "{:#x?}", u64::osi_read(cpu, ptr)?),
                        IntType::I32 => write!(f, "{}", i32::osi_read(cpu, ptr)?),
                        IntType::I64 => write!(f, "{}", i64::osi_read(cpu, ptr)?),
                    };

                    Ok::<_, panda::GuestReadFail>(())
                })()
                .is_err();

                if is_err {
                    write!(f, "({}*){:#x?}", self.name(), ptr);
                }
            }

            Self::VoidPtr => {
                write!(f, "(void*){:#x?}", ptr);
            }

            Self::Const(inner) => {
                inner.read_display_ptr(cpu, f, ptr);
            }

            Self::CStr => {
                write!(f, "(char**){:#x?}", ptr);
            }
        }
    }
}

fn display_base<W>(val: target_ptr_t, size: target_ptr_t, signed: bool, f: &mut W)
where
    W: Write,
{
    match (size, signed) {
        (1, false) => write!(f, "{:#x?}", val as u8),
        (1, true) => write!(f, "{}", val as i8),
        (2, false) => write!(f, "{:#x?}", val as u16),
        (2, true) => write!(f, "{}", val as i16),
        (4, false) => write!(f, "{:#x?}", val as u32),
        (4, true) => write!(f, "{}", val as i32),
        (8, false) => write!(f, "{:#x?}", val as u64),
        (8, true) => write!(f, "{}", val as i64),
        (size, signed) => panic!("Invalid int: size={}, signed={}", size, signed),
    }
    .unwrap();
}

impl From<Type> for OsiArgType {
    fn from(c_type: Type) -> Self {
        to_osi_arg_type(c_type)
    }
}

fn int(x: IntType) -> Option<OsiArgType> {
    Some(OsiArgType::FixedWidth(x))
}

fn find_missing_type(name: &str) -> Option<OsiArgType> {
    match name {
        "unsigned" => cosi::base_type_from_name("int").map(OsiArgType::UnsignedBase),
        "size_t" => cosi::base_type_from_name("sizetype").map(OsiArgType::UnsignedBase),

        "long" => cosi::base_type_from_name("long int").map(OsiArgType::Base),
        "ssize_t" => cosi::base_type_from_name("sizetype").map(OsiArgType::Base),

        "__u64" | "u64" => int(IntType::U64),
        "__u32" | "u32" => int(IntType::U32),

        "__s64" | "s64" => int(IntType::I64),
        "__s32" | "s32" => int(IntType::I32),

        _ => None,
    }
}

fn to_osi_arg_type(c_type: Type) -> OsiArgType {
    match c_type {
        Type::Const(inner) => OsiArgType::Const(Box::new(to_osi_arg_type(*inner))),

        Type::Ptr(inner) => match *inner {
            // void*
            Type::Ident(ident) if ident == "void" => OsiArgType::VoidPtr,

            // char*
            Type::Ident(ident) if ident == "char" => OsiArgType::CStr,

            // const char*
            Type::Const(inner) if matches!(&*inner, Type::Ident(ident) if ident == "char") => {
                OsiArgType::Const(Box::new(OsiArgType::CStr))
            }

            // T*
            inner => OsiArgType::Ptr(Box::new(to_osi_arg_type(inner))),
        },

        Type::Unsigned(name) => cosi::base_type_from_name(&name)
            .map(OsiArgType::UnsignedBase)
            .or_else(|| {
                cosi::base_type_from_name(&format!("[unsigned] {}", name))
                    .map(OsiArgType::UnsignedBase)
            })
            .or_else(|| find_missing_type(&name).map(OsiArgType::make_unsigned))
            .unwrap_or(OsiArgType::Fallback),

        Type::Ident(name) if name == "unsigned" => cosi::base_type_from_name("int")
            .map(OsiArgType::UnsignedBase)
            .unwrap_or(OsiArgType::Fallback),

        Type::Ident(ref name) | Type::Struct(ref name) | Type::Union(ref name) => {
            cosi::type_from_name(&name)
                .map(OsiArgType::Struct)
                .or_else(|| cosi::enum_from_name(&name).map(OsiArgType::Enum))
                .or_else(|| cosi::base_type_from_name(&name).map(OsiArgType::Base))
                .or_else(|| find_missing_type(&name))
                .unwrap_or(OsiArgType::Fallback)
        }
    }
}

//fn osi_type_from_map()
