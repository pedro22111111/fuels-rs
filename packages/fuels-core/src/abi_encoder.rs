use fuel_types::bytes::padded_len_usize;
use fuels_types::{
    constants::WORD_SIZE,
    errors::Result,
    pad_string, pad_u16, pad_u32, pad_u8,
    unresolved_bytes::{Data, UnresolvedBytes},
    EnumSelector, StringToken, Token,
};
use itertools::Itertools;

pub struct ABIEncoder;

impl ABIEncoder {
    /// Encodes `Token`s in `args` following the ABI specs defined
    /// [here](https://github.com/FuelLabs/fuel-specs/blob/master/specs/protocol/abi.md)
    pub fn encode(args: &[Token]) -> Result<UnresolvedBytes> {
        let data = Self::encode_tokens(args)?;

        Ok(UnresolvedBytes::new(data))
    }

    fn encode_tokens(tokens: &[Token]) -> Result<Vec<Data>> {
        tokens
            .iter()
            .map(Self::encode_token)
            .flatten_ok()
            .collect::<Result<Vec<_>>>()
    }

    fn encode_token(arg: &Token) -> Result<Vec<Data>> {
        let encoded_token = match arg {
            Token::U8(arg_u8) => vec![Self::encode_u8(*arg_u8)],
            Token::U16(arg_u16) => vec![Self::encode_u16(*arg_u16)],
            Token::U32(arg_u32) => vec![Self::encode_u32(*arg_u32)],
            Token::U64(arg_u64) => vec![Self::encode_u64(*arg_u64)],
            Token::Bool(arg_bool) => vec![Self::encode_bool(*arg_bool)],
            Token::B256(arg_bits256) => vec![Self::encode_b256(arg_bits256)],
            Token::Array(arg_array) => Self::encode_array(arg_array)?,
            Token::Vector(data) => Self::encode_vector(data)?,
            Token::String(arg_string) => vec![Self::encode_string(arg_string)?],
            Token::Struct(arg_struct) => Self::encode_struct(arg_struct)?,
            Token::Enum(arg_enum) => Self::encode_enum(arg_enum)?,
            Token::Tuple(arg_tuple) => Self::encode_tuple(arg_tuple)?,
            Token::Unit => vec![Self::encode_unit()],
            Token::RawSlice(data) => Self::encode_raw_slice(data)?,
            Token::Bytes(data) => Self::encode_bytes(data.to_vec())?,
        };

        Ok(encoded_token)
    }

    fn encode_unit() -> Data {
        Data::Inline(vec![0; WORD_SIZE])
    }

    fn encode_tuple(arg_tuple: &[Token]) -> Result<Vec<Data>> {
        Self::encode_tokens(arg_tuple)
    }

    fn encode_struct(subcomponents: &[Token]) -> Result<Vec<Data>> {
        Self::encode_tokens(subcomponents)
    }

    fn encode_array(arg_array: &[Token]) -> Result<Vec<Data>> {
        Self::encode_tokens(arg_array)
    }

    fn encode_string(arg_string: &StringToken) -> Result<Data> {
        Ok(Data::Inline(pad_string(arg_string.get_encodable_str()?)))
    }

    fn encode_b256(arg_bits256: &[u8; 32]) -> Data {
        Data::Inline(arg_bits256.to_vec())
    }

    fn encode_bool(arg_bool: bool) -> Data {
        Data::Inline(pad_u8(u8::from(arg_bool)).to_vec())
    }

    fn encode_u64(arg_u64: u64) -> Data {
        Data::Inline(arg_u64.to_be_bytes().to_vec())
    }

    fn encode_u32(arg_u32: u32) -> Data {
        Data::Inline(pad_u32(arg_u32).to_vec())
    }

    fn encode_u16(arg_u16: u16) -> Data {
        Data::Inline(pad_u16(arg_u16).to_vec())
    }

    fn encode_u8(arg_u8: u8) -> Data {
        Data::Inline(pad_u8(arg_u8).to_vec())
    }

    fn encode_enum(selector: &EnumSelector) -> Result<Vec<Data>> {
        let (discriminant, token_within_enum, variants) = selector;

        let mut encoded_enum = vec![Self::encode_discriminant(*discriminant)];

        // Enums that contain only Units as variants have only their discriminant encoded.
        if !variants.only_units_inside() {
            let variant_param_type = variants.param_type_of_variant(*discriminant)?;
            let padding_amount = variants.compute_padding_amount(variant_param_type);

            encoded_enum.push(Data::Inline(vec![0; padding_amount]));

            let token_data = Self::encode_token(token_within_enum)?;
            encoded_enum.extend(token_data);
        }

        Ok(encoded_enum)
    }

    fn encode_discriminant(discriminant: u8) -> Data {
        Self::encode_u8(discriminant)
    }

    fn encode_vector(data: &[Token]) -> Result<Vec<Data>> {
        let encoded_data = Self::encode_tokens(data)?;
        let cap = data.len() as u64;
        let len = data.len() as u64;

        // A vector is expected to be encoded as 3 WORDs -- a ptr, a cap and a
        // len. This means that we must place the encoded vector elements
        // somewhere else. Hence the use of Data::Dynamic which will, when
        // resolved, leave behind in its place only a pointer to the actual
        // data.
        Ok(vec![
            Data::Dynamic(encoded_data),
            Self::encode_u64(cap),
            Self::encode_u64(len),
        ])
    }

    fn encode_raw_slice(data: &[u64]) -> Result<Vec<Data>> {
        let encoded_data = data
            .iter()
            .map(|&word| Self::encode_u64(word))
            .collect::<Vec<_>>();

        let num_bytes = data.len() * WORD_SIZE;

        let len = Self::encode_u64(num_bytes as u64);
        Ok(vec![Data::Dynamic(encoded_data), len])
    }

    fn encode_bytes(mut data: Vec<u8>) -> Result<Vec<Data>> {
        let len = data.len();

        zeropad_to_word_alignment(&mut data);

        let cap = data.len() as u64;
        let encoded_data = vec![Data::Inline(data)];

        Ok(vec![
            Data::Dynamic(encoded_data),
            Self::encode_u64(cap),
            Self::encode_u64(len as u64),
        ])
    }
}

fn zeropad_to_word_alignment(data: &mut Vec<u8>) {
    let padded_length = padded_len_usize(data.len());
    data.resize(padded_length, 0);
}

#[cfg(test)]
mod tests {
    use fuels_macros::{Parameterize, Tokenizable};
    use fuels_types::{errors::Result, traits::Tokenizable, Bits256, SizedAsciiString};
    use itertools::chain;

    use super::*;

    const VEC_METADATA_SIZE: usize = 3 * WORD_SIZE;
    const DISCRIMINANT_SIZE: usize = WORD_SIZE;

    #[test]
    fn encoding_u32() {
        assert_expected_encoding(
            u32::MAX.into_token(),
            &[0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff],
        );
    }

    #[test]
    fn encoding_u64() {
        assert_expected_encoding(
            u64::MAX.into_token(),
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
    }

    #[test]
    fn encode_function_with_bool_type() {
        assert_expected_encoding(true.into_token(), &[0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1]);
    }

    #[test]
    fn encode_function_with_bits256_type() {
        let bytes = [
            0xd5, 0x57, 0x9c, 0x46, 0xdf, 0xcc, 0x7f, 0x18, 0x20, 0x70, 0x13, 0xe6, 0x5b, 0x44,
            0xe4, 0xcb, 0x4e, 0x2c, 0x22, 0x98, 0xf4, 0xac, 0x45, 0x7b, 0xa8, 0xf8, 0x27, 0x43,
            0xf3, 0x1e, 0x93, 0xb,
        ];

        assert_expected_encoding(Token::B256(bytes), &bytes);
    }

    fn assert_expected_encoding(token: Token, expected_encoding: &[u8]) {
        let encoded = ABIEncoder::encode(&[token]).unwrap().resolve(0);

        assert_eq!(&encoded, expected_encoding)
    }

    #[test]
    fn array_u8_encoding() {
        let token = [1u8, 2, 3].into_token();

        let expected = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3,
        ];

        assert_expected_encoding(token, &expected);
    }

    #[test]
    fn string_encoding() {
        let token = Token::String(StringToken::new("This is a full sentence".into(), 23));

        let expected = [
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x66, 0x75, 0x6c, 0x6c,
            0x20, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65, 0x00,
        ];

        assert_expected_encoding(token, &expected);
    }

    #[test]
    fn encode_function_with_struct() {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        struct SomeStruct {
            field_a: u8,
            field_b: bool,
        }

        let token = SomeStruct {
            field_a: 1,
            field_b: true,
        }
        .into_token();

        let expected = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
        ];

        assert_expected_encoding(token, &expected);
    }

    #[test]
    fn encode_function_with_enum() {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        enum SomeEnum {
            V1(u32),
            V2(bool),
        }

        let token = SomeEnum::V1(42).into_token();

        let expected = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2a,
        ];

        assert_expected_encoding(token, &expected);
    }

    #[test]
    fn enums_are_padded_to_the_size_of_the_biggest_variant() -> Result<()> {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        enum SomeEnum {
            V1(Bits256),
            V2(u64),
        }
        let token = SomeEnum::V2(42).into_token();

        let enum_discriminant_enc = vec![0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1];
        let enum_padding = vec![0x0; 24];
        let u64_enc = vec![0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2a];

        let expected: Vec<u8> = [enum_discriminant_enc, enum_padding, u64_enc].concat();

        assert_expected_encoding(token, &expected);

        Ok(())
    }

    #[test]
    fn encoding_enums_with_deeply_nested_types() -> Result<()> {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        enum TopLevelEnum {
            V1(SomeStruct),
            V2(bool),
            V3(u64),
        }

        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        struct SomeStruct {
            deeper_enum: DeeperEnum,
            some_number: u32,
        }

        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        enum DeeperEnum {
            V1(bool),
            V2(SizedAsciiString<10>),
        }

        let token = TopLevelEnum::V1(SomeStruct {
            deeper_enum: DeeperEnum::V2("0123456789".try_into()?),
            some_number: 11332,
        })
        .into_token();

        let top_lvl_discriminant_enc = vec![0x0; 8];
        let deeper_enum_discriminant_enc = vec![0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1];
        let some_number_enc = vec![0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2c, 0x44];
        let str_enc = vec![
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0,
        ];
        let correct_encoding: Vec<u8> = [
            top_lvl_discriminant_enc,
            deeper_enum_discriminant_enc,
            str_enc,
            some_number_enc,
        ]
        .concat();

        assert_expected_encoding(token, &correct_encoding);

        Ok(())
    }

    #[test]
    fn encode_function_with_nested_structs() -> Result<()> {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        struct Foo {
            x: u16,
            y: Bar,
        }

        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        struct Bar {
            a: bool,
            b: [u8; 2],
        }

        let token = Foo {
            x: 10,
            y: Bar { a: true, b: [1, 2] },
        }
        .into_token();

        let expected = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2,
        ];

        assert_expected_encoding(token, &expected);

        Ok(())
    }

    #[test]
    fn encode_comprehensive_function() -> Result<()> {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        struct Foo {
            x: u16,
            y: Bar,
        }

        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        struct Bar {
            a: bool,
            b: [u8; 2],
        }

        let foo = Foo {
            x: 10,
            y: Bar { a: true, b: [1, 2] },
        }
        .into_token();

        let u8_arr = [1u8, 2].into_token();

        let b256_bytes = [
            0xd5, 0x57, 0x9c, 0x46, 0xdf, 0xcc, 0x7f, 0x18, 0x20, 0x70, 0x13, 0xe6, 0x5b, 0x44,
            0xe4, 0xcb, 0x4e, 0x2c, 0x22, 0x98, 0xf4, 0xac, 0x45, 0x7b, 0xa8, 0xf8, 0x27, 0x43,
            0xf3, 0x1e, 0x93, 0xb,
        ];

        let b256 = Token::B256(b256_bytes);

        let string = Token::String(StringToken::new("This is a full sentence".into(), 23));

        let encoded = ABIEncoder::encode(&[foo, u8_arr, b256, string])?.resolve(0);

        let expected = vec![
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, // foo.x == 10u16
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // foo.y.a == true
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // foo.b.0 == 1u8
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, // foo.b.1 == 2u8
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // u8[2].0 == 1u8
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, // u8[2].0 == 2u8
            0xd5, 0x57, 0x9c, 0x46, 0xdf, 0xcc, 0x7f, 0x18, // b256
            0x20, 0x70, 0x13, 0xe6, 0x5b, 0x44, 0xe4, 0xcb, // b256
            0x4e, 0x2c, 0x22, 0x98, 0xf4, 0xac, 0x45, 0x7b, // b256
            0xa8, 0xf8, 0x27, 0x43, 0xf3, 0x1e, 0x93, 0xb, // b256
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, // str[23]
            0x61, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x73, // str[23]
            0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65, 0x0, // str[23]
        ];

        assert_eq!(expected, encoded);
        Ok(())
    }

    #[test]
    fn enums_with_only_unit_variants_are_encoded_in_one_word() {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        enum OnlyUnits {
            V1,
            V2,
        }

        let token = OnlyUnits::V2.into_token();

        assert_expected_encoding(token, &[0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn units_in_composite_types_are_encoded_in_one_word() {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        struct HasUnits {
            unit: (),
            number: u32,
        }

        let token = HasUnits {
            unit: (),
            number: 5,
        }
        .into_token();
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];

        assert_expected_encoding(token, &expected);
    }

    #[test]
    fn enums_with_units_are_correctly_padded() {
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        enum HasUnits {
            V1(Bits256),
            V2,
        }

        let token = HasUnits::V2.into_token();

        let discriminant = vec![0, 0, 0, 0, 0, 0, 0, 1];
        let padding = vec![0; 32];
        let expected: Vec<u8> = [discriminant, padding].concat();

        assert_expected_encoding(token, &expected);
    }

    #[test]
    fn vector_has_ptr_cap_len_and_then_data() -> Result<()> {
        // arrange
        let offset: u8 = 150;
        let token = vec![5u64].into_token();

        // act
        let result = ABIEncoder::encode(&[token])?.resolve(offset as u64);

        // assert
        let ptr = [0, 0, 0, 0, 0, 0, 0, 3 * WORD_SIZE as u8 + offset];
        let cap = [0, 0, 0, 0, 0, 0, 0, 1];
        let len = [0, 0, 0, 0, 0, 0, 0, 1];
        let data = [0, 0, 0, 0, 0, 0, 0, 5];

        let expected = chain!(ptr, cap, len, data).collect::<Vec<_>>();

        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn data_from_two_vectors_aggregated_at_the_end() -> Result<()> {
        // arrange
        let offset: u8 = 40;
        let vec_1 = vec![5u64].into_token();
        let vec_2 = vec![6u64].into_token();

        // act
        let result = ABIEncoder::encode(&[vec_1, vec_2])?.resolve(offset as u64);

        // assert
        let vec1_data_offset = 6 * WORD_SIZE as u8 + offset;
        let vec1_ptr = [0, 0, 0, 0, 0, 0, 0, vec1_data_offset];
        let vec1_cap = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec1_len = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec1_data = [0, 0, 0, 0, 0, 0, 0, 5];

        let vec2_data_offset = vec1_data_offset + vec1_data.len() as u8;
        let vec2_ptr = [0, 0, 0, 0, 0, 0, 0, vec2_data_offset];
        let vec2_cap = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec2_len = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec2_data = [0, 0, 0, 0, 0, 0, 0, 6];

        let expected = chain!(
            vec1_ptr, vec1_cap, vec1_len, vec2_ptr, vec2_cap, vec2_len, vec1_data, vec2_data,
        )
        .collect::<Vec<_>>();

        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn a_vec_in_an_enum() -> Result<()> {
        // arrange
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        enum HasVec {
            V1(Bits256),
            V2(Vec<u64>),
        }

        let offset = 40;
        let token = HasVec::V2(vec![5]).into_token();

        // act
        let result = ABIEncoder::encode(&[token])?.resolve(offset as u64);

        // assert
        let discriminant = vec![0, 0, 0, 0, 0, 0, 0, 1];

        const PADDING: usize = std::mem::size_of::<[u8; 32]>() - VEC_METADATA_SIZE;

        let vec1_ptr = ((DISCRIMINANT_SIZE + PADDING + VEC_METADATA_SIZE + offset) as u64)
            .to_be_bytes()
            .to_vec();
        let vec1_cap = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec1_len = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec1_data = [0, 0, 0, 0, 0, 0, 0, 5];

        let expected = chain!(
            discriminant,
            vec![0; PADDING],
            vec1_ptr,
            vec1_cap,
            vec1_len,
            vec1_data
        )
        .collect::<Vec<u8>>();

        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn an_enum_in_a_vec() -> Result<()> {
        // arrange
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        enum SomeEnum {
            V1(Bits256),
            V2(u8),
        }
        let offset = 40;
        let vec_token = vec![SomeEnum::V2(8)].into_token();

        // act
        let result = ABIEncoder::encode(&[vec_token])?.resolve(offset as u64);

        // assert
        const PADDING: usize = std::mem::size_of::<[u8; 32]>() - WORD_SIZE;

        let vec1_ptr = ((VEC_METADATA_SIZE + offset) as u64).to_be_bytes().to_vec();
        let vec1_cap = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec1_len = [0, 0, 0, 0, 0, 0, 0, 1];
        let discriminant = 1u64.to_be_bytes();
        let vec1_data = chain!(discriminant, [0; PADDING], 8u64.to_be_bytes()).collect::<Vec<_>>();

        let expected = chain!(vec1_ptr, vec1_cap, vec1_len, vec1_data).collect::<Vec<u8>>();

        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn a_vec_in_a_struct() -> Result<()> {
        // arrange
        #[derive(Parameterize, Tokenizable)]
        #[FuelsTypesPath("fuels_types")]
        struct HasAVec {
            the_vec: Vec<u64>,
            number: u8,
        }

        let offset = 40;
        let token = HasAVec {
            the_vec: vec![5],
            number: 9,
        }
        .into_token();

        // act
        let result = ABIEncoder::encode(&[token])?.resolve(offset as u64);

        // assert
        let vec1_ptr = ((VEC_METADATA_SIZE + WORD_SIZE + offset) as u64)
            .to_be_bytes()
            .to_vec();
        let vec1_cap = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec1_len = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec1_data = [0, 0, 0, 0, 0, 0, 0, 5];

        let expected = chain!(
            vec1_ptr,
            vec1_cap,
            vec1_len,
            [0, 0, 0, 0, 0, 0, 0, 9],
            vec1_data
        )
        .collect::<Vec<u8>>();

        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn a_vec_in_a_vec() -> Result<()> {
        // arrange
        let offset = 40;
        let token = vec![vec![5u8, 6]].into_token();

        // act
        let result = ABIEncoder::encode(&[token])?.resolve(offset as u64);

        // assert
        let vec1_data_offset = (VEC_METADATA_SIZE + offset) as u64;
        let vec1_ptr = vec1_data_offset.to_be_bytes().to_vec();
        let vec1_cap = [0, 0, 0, 0, 0, 0, 0, 1];
        let vec1_len = [0, 0, 0, 0, 0, 0, 0, 1];

        let vec2_ptr = (vec1_data_offset + VEC_METADATA_SIZE as u64)
            .to_be_bytes()
            .to_vec();
        let vec2_cap = [0, 0, 0, 0, 0, 0, 0, 2];
        let vec2_len = [0, 0, 0, 0, 0, 0, 0, 2];
        let vec2_data = [0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6];

        let vec1_data = chain!(vec2_ptr, vec2_cap, vec2_len, vec2_data).collect::<Vec<_>>();

        let expected = chain!(vec1_ptr, vec1_cap, vec1_len, vec1_data).collect::<Vec<u8>>();

        assert_eq!(result, expected);

        Ok(())
    }

    #[test]
    fn encoding_bytes() -> Result<()> {
        // arrange
        let token = Token::Bytes(vec![1, 2, 3]);
        let offset = 40;

        // act
        let encoded_bytes = ABIEncoder::encode(&[token])?.resolve(offset);

        // assert
        let ptr = [0, 0, 0, 0, 0, 0, 0, 64];
        let cap = [0, 0, 0, 0, 0, 0, 0, 8];
        let len = [0, 0, 0, 0, 0, 0, 0, 3];
        let data = [1, 2, 3, 0, 0, 0, 0, 0];

        let expected_encoded_bytes = [ptr, cap, len, data].concat();

        assert_eq!(expected_encoded_bytes, encoded_bytes);

        Ok(())
    }

    #[test]
    fn encoding_raw_slices() -> Result<()> {
        // arrange
        let token = Token::RawSlice(vec![1, 2, 3]);
        let offset = 40;

        // act
        let encoded_bytes = ABIEncoder::encode(&[token])?.resolve(offset);

        // assert
        let ptr = vec![0, 0, 0, 0, 0, 0, 0, 56];
        let len = vec![0, 0, 0, 0, 0, 0, 0, 24];
        let data = [
            [0, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 2],
            [0, 0, 0, 0, 0, 0, 0, 3],
        ]
        .concat();

        let expected_encoded_bytes = [ptr, len, data].concat();

        assert_eq!(expected_encoded_bytes, encoded_bytes);

        Ok(())
    }
}
