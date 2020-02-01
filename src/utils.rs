// Nice hash map initializer macro.
// Source: https://stackoverflow.com/questions/28392008/more-concise-hashmap-initialization
//macro_rules! hashmap {
//    ($( $key: expr => $val: expr ),*) => {{
//         let mut map = ::std::collections::HashMap::new();
//         $( map.insert($key, $val); )*
//         map
//    }}
//}