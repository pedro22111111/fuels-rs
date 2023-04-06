use itertools::chain;
use strum_macros::EnumString;

use crate::{
    constants::WORD_SIZE,
    enum_variants::EnumVariants,
    errors::{error, Error, Result},
};

#[derive(Debug, Clone, EnumString, PartialEq, Eq, Default)]
#[strum(ascii_case_insensitive)]
pub enum ParamType {
    #[default]
    U8,
    U16,
    U32,
    U64,
    Bool,
    B256,
    // The Unit ParamType is used for unit variants in Enums. The corresponding type field is `()`,
    // similar to Rust.
    Unit,
    Array(Box<ParamType>, usize),
    Vector(Box<ParamType>),
    #[strum(serialize = "str")]
    String(usize),
    #[strum(disabled)]
    Struct {
        fields: Vec<ParamType>,
        generics: Vec<ParamType>,
    },
    #[strum(disabled)]
    Enum {
        variants: EnumVariants,
        generics: Vec<ParamType>,
    },
    Tuple(Vec<ParamType>),
    RawSlice,
    Bytes,
}

pub enum ReturnLocation {
    Return,
    ReturnData,
}

impl ParamType {
    // Depending on the type, the returned value will be stored
    // either in `Return` or `ReturnData`.
    pub fn get_return_location(&self) -> ReturnLocation {
        match self {
            Self::Unit | Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::Bool => {
                ReturnLocation::Return
            }

            _ => ReturnLocation::ReturnData,
        }
    }

    /// Given a [ParamType], return the number of elements of that [ParamType] that can fit in
    /// `available_bytes`: it is the length of the corresponding heap type.
    pub fn calculate_num_of_elements(
        param_type: &ParamType,
        available_bytes: usize,
    ) -> Result<usize> {
        let memory_size = param_type.compute_encoding_width() * WORD_SIZE;
        let remainder = available_bytes % memory_size;
        if remainder != 0 {
            return Err(error!(
                InvalidData,
                "{remainder} extra bytes detected while decoding heap type"
            ));
        }
        Ok(available_bytes / memory_size)
    }

    pub fn contains_nested_heap_types(&self) -> bool {
        match &self {
            ParamType::Vector(param_type) => param_type.uses_heap_types(),
            ParamType::Bytes => false,
            _ => self.uses_heap_types(),
        }
    }

    fn uses_heap_types(&self) -> bool {
        match &self {
            ParamType::Vector(..) | ParamType::Bytes => true,
            ParamType::Array(param_type, ..) => param_type.uses_heap_types(),
            ParamType::Tuple(param_types, ..) => Self::any_nested_heap_types(param_types),
            ParamType::Enum {
                generics, variants, ..
            } => {
                let variants_types = variants.param_types();
                Self::any_nested_heap_types(chain!(generics, variants_types))
            }
            ParamType::Struct {
                fields, generics, ..
            } => Self::any_nested_heap_types(chain!(fields, generics)),
            _ => false,
        }
    }

    fn any_nested_heap_types<'a>(param_types: impl IntoIterator<Item = &'a ParamType>) -> bool {
        param_types
            .into_iter()
            .any(|param_type| param_type.uses_heap_types())
    }

    pub fn is_vm_heap_type(&self) -> bool {
        matches!(self, ParamType::Vector(..) | ParamType::Bytes)
    }

    /// Compute the inner memory size of a containing heap type (`Bytes` or `Vec`s).
    pub fn heap_inner_element_size(&self) -> Option<usize> {
        match &self {
            ParamType::Vector(inner_param_type) => {
                Some(inner_param_type.compute_encoding_width() * WORD_SIZE)
            }
            // `Bytes` type is byte-packed in the VM, so it's the size of an u8
            ParamType::Bytes => Some(std::mem::size_of::<u8>()),
            _ => None,
        }
    }

    /// Calculates the number of `WORD`s the VM expects this parameter to be encoded in.
    pub fn compute_encoding_width(&self) -> usize {
        const fn count_words(bytes: usize) -> usize {
            let q = bytes / WORD_SIZE;
            let r = bytes % WORD_SIZE;
            match r == 0 {
                true => q,
                false => q + 1,
            }
        }

        match &self {
            ParamType::Unit
            | ParamType::U8
            | ParamType::U16
            | ParamType::U32
            | ParamType::U64
            | ParamType::Bool => 1,
            ParamType::RawSlice => 2,
            ParamType::Vector(_) | ParamType::Bytes => 3,
            ParamType::B256 => 4,
            ParamType::Array(param, count) => param.compute_encoding_width() * count,
            ParamType::String(len) => count_words(*len),
            ParamType::Struct { fields, .. } => fields
                .iter()
                .map(|param_type| param_type.compute_encoding_width())
                .sum(),
            ParamType::Enum { variants, .. } => variants.compute_encoding_width_of_enum(),
            ParamType::Tuple(params) => params.iter().map(|p| p.compute_encoding_width()).sum(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::param_types::ParamType;

    const WIDTH_OF_B256: usize = 4;
    const WIDTH_OF_U32: usize = 1;
    const WIDTH_OF_BOOL: usize = 1;

    #[test]
    fn array_size_dependent_on_num_of_elements() {
        const NUM_ELEMENTS: usize = 11;
        let param = ParamType::Array(Box::new(ParamType::B256), NUM_ELEMENTS);

        let width = param.compute_encoding_width();

        let expected = NUM_ELEMENTS * WIDTH_OF_B256;
        assert_eq!(expected, width);
    }

    #[test]
    fn string_size_dependent_on_num_of_elements() {
        const NUM_ASCII_CHARS: usize = 9;
        let param = ParamType::String(NUM_ASCII_CHARS);

        let width = param.compute_encoding_width();

        // 2 WORDS or 16 B are enough to fit 9 ascii chars
        assert_eq!(2, width);
    }

    #[test]
    fn structs_are_just_all_elements_combined() {
        let inner_struct = ParamType::Struct {
            fields: vec![ParamType::U32, ParamType::U32],
            generics: vec![],
        };

        let a_struct = ParamType::Struct {
            fields: vec![ParamType::B256, ParamType::Bool, inner_struct],
            generics: vec![],
        };

        let width = a_struct.compute_encoding_width();

        const INNER_STRUCT_WIDTH: usize = WIDTH_OF_U32 * 2;
        const EXPECTED_WIDTH: usize = WIDTH_OF_B256 + WIDTH_OF_BOOL + INNER_STRUCT_WIDTH;
        assert_eq!(EXPECTED_WIDTH, width);
    }

    #[test]
    fn enums_are_as_big_as_their_biggest_variant_plus_a_word() -> Result<()> {
        let fields = vec![ParamType::B256];
        let inner_struct = ParamType::Struct {
            fields,
            generics: vec![],
        };
        let types = vec![ParamType::U32, inner_struct];
        let param = ParamType::Enum {
            variants: EnumVariants::new(types)?,
            generics: vec![],
        };

        let width = param.compute_encoding_width();

        const INNER_STRUCT_SIZE: usize = WIDTH_OF_B256;
        const EXPECTED_WIDTH: usize = INNER_STRUCT_SIZE + 1;
        assert_eq!(EXPECTED_WIDTH, width);
        Ok(())
    }

    #[test]
    fn tuples_are_just_all_elements_combined() {
        let inner_tuple = ParamType::Tuple(vec![ParamType::B256]);
        let param = ParamType::Tuple(vec![ParamType::U32, inner_tuple]);

        let width = param.compute_encoding_width();

        const INNER_TUPLE_WIDTH: usize = WIDTH_OF_B256;
        const EXPECTED_WIDTH: usize = WIDTH_OF_U32 + INNER_TUPLE_WIDTH;
        assert_eq!(EXPECTED_WIDTH, width);
    }

    #[test]
    fn contains_nested_heap_types_false_on_simple_types() -> Result<()> {
        // Simple types cannot have nested heap types
        assert!(!ParamType::Unit.contains_nested_heap_types());
        assert!(!ParamType::U8.contains_nested_heap_types());
        assert!(!ParamType::U16.contains_nested_heap_types());
        assert!(!ParamType::U32.contains_nested_heap_types());
        assert!(!ParamType::U64.contains_nested_heap_types());
        assert!(!ParamType::Bool.contains_nested_heap_types());
        assert!(!ParamType::B256.contains_nested_heap_types());
        assert!(!ParamType::String(10).contains_nested_heap_types());
        assert!(!ParamType::RawSlice.contains_nested_heap_types());
        assert!(!ParamType::Bytes.contains_nested_heap_types());
        Ok(())
    }

    #[test]
    fn test_complex_types_for_nested_heap_types_containing_vectors() -> Result<()> {
        let base_vector = ParamType::Vector(Box::from(ParamType::U8));
        let param_types_no_nested_vec = vec![ParamType::U64, ParamType::U32];
        let param_types_nested_vec = vec![ParamType::Unit, ParamType::Bool, base_vector.clone()];

        let is_nested = |param_type: ParamType| assert!(param_type.contains_nested_heap_types());
        let not_nested = |param_type: ParamType| assert!(!param_type.contains_nested_heap_types());

        not_nested(base_vector.clone());
        is_nested(ParamType::Vector(Box::from(base_vector.clone())));

        not_nested(ParamType::Array(Box::from(ParamType::U8), 10));
        is_nested(ParamType::Array(Box::from(base_vector), 10));

        not_nested(ParamType::Tuple(param_types_no_nested_vec.clone()));
        is_nested(ParamType::Tuple(param_types_nested_vec.clone()));

        not_nested(ParamType::Struct {
            generics: param_types_no_nested_vec.clone(),
            fields: param_types_no_nested_vec.clone(),
        });
        is_nested(ParamType::Struct {
            generics: param_types_nested_vec.clone(),
            fields: param_types_no_nested_vec.clone(),
        });
        is_nested(ParamType::Struct {
            generics: param_types_no_nested_vec.clone(),
            fields: param_types_nested_vec.clone(),
        });

        not_nested(ParamType::Enum {
            variants: EnumVariants::new(param_types_no_nested_vec.clone())?,
            generics: param_types_no_nested_vec.clone(),
        });
        is_nested(ParamType::Enum {
            variants: EnumVariants::new(param_types_nested_vec.clone())?,
            generics: param_types_no_nested_vec.clone(),
        });
        is_nested(ParamType::Enum {
            variants: EnumVariants::new(param_types_no_nested_vec)?,
            generics: param_types_nested_vec,
        });
        Ok(())
    }

    #[test]
    fn test_complex_types_for_nested_heap_types_containing_bytes() -> Result<()> {
        let base_bytes = ParamType::Bytes;
        let param_types_no_nested_bytes = vec![ParamType::U64, ParamType::U32];
        let param_types_nested_bytes = vec![ParamType::Unit, ParamType::Bool, base_bytes.clone()];

        let is_nested = |param_type: ParamType| assert!(param_type.contains_nested_heap_types());
        let not_nested = |param_type: ParamType| assert!(!param_type.contains_nested_heap_types());

        not_nested(base_bytes.clone());
        is_nested(ParamType::Vector(Box::from(base_bytes.clone())));

        not_nested(ParamType::Array(Box::from(ParamType::U8), 10));
        is_nested(ParamType::Array(Box::from(base_bytes), 10));

        not_nested(ParamType::Tuple(param_types_no_nested_bytes.clone()));
        is_nested(ParamType::Tuple(param_types_nested_bytes.clone()));

        let not_nested_struct = ParamType::Struct {
            generics: param_types_no_nested_bytes.clone(),
            fields: param_types_no_nested_bytes.clone(),
        };
        not_nested(not_nested_struct);

        let nested_struct = ParamType::Struct {
            generics: param_types_nested_bytes.clone(),
            fields: param_types_no_nested_bytes.clone(),
        };
        is_nested(nested_struct);

        let nested_struct = ParamType::Struct {
            generics: param_types_no_nested_bytes.clone(),
            fields: param_types_nested_bytes.clone(),
        };
        is_nested(nested_struct);

        let not_nested_enum = ParamType::Enum {
            variants: EnumVariants::new(param_types_no_nested_bytes.clone())?,
            generics: param_types_no_nested_bytes.clone(),
        };
        not_nested(not_nested_enum);

        let nested_enum = ParamType::Enum {
            variants: EnumVariants::new(param_types_nested_bytes.clone())?,
            generics: param_types_no_nested_bytes.clone(),
        };
        is_nested(nested_enum);

        let nested_enum = ParamType::Enum {
            variants: EnumVariants::new(param_types_no_nested_bytes)?,
            generics: param_types_nested_bytes,
        };
        is_nested(nested_enum);

        Ok(())
    }
}
