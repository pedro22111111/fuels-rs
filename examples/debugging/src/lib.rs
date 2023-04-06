#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use fuel_abi_types::{
        fn_selector::resolve_fn_selector as new_resolve_fn_selector, program_abi::ProgramABI,
    };
    use fuels::types::{
        errors::Result, fn_selector::resolve_fn_selector, traits::Parameterize, SizedAsciiString,
    };

    #[test]
    fn get_a_fn_selector() {
        // ANCHOR: example_fn_selector
        // fn some_fn_name(arg1: Vec<str[3]>, arg2: u8)
        let fn_name = "some_fn_name";
        let inputs = [Vec::<SizedAsciiString<3>>::param_type(), u8::param_type()];

        let selector = resolve_fn_selector(fn_name, &inputs);

        assert_eq!(selector, [0, 0, 0, 0, 7, 161, 3, 203]);
        // ANCHOR_END: example_fn_selector
    }
}
