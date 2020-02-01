//use std::fmt::{Display, Formatter, Result};
//use crate::hasher::HashError;
//
//#[derive(Debug)]
//pub struct IocSearchResult {
//    pub ioc_id: IocId,
//    pub data: Vec<String>,
//}
//
//impl IocSearchResult {
//    pub fn new(index: IocId, data: Vec<String>) -> IocSearchResult { IocSearchResult { ioc_id: index, data } }
//    pub fn new_failed<T: Display>(index: IocId, error: T) -> IocSearchResult {
//        IocSearchResult {
//            ioc_id: index,
//            data: vec![error.to_string()],
//        }
//    }
//}
//
//#[derive(Debug)]
//pub struct IocSearchError {
//    pub ioc_id: IocId,
//    pub kind: String,
//    pub message: String,
//}
//
//impl Display for IocSearchError {
//    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
//        write!(f, "IocError(ioc_index: {}, kind: {}, message: {})", self.ioc_id, self.kind, self.message)
//    }
//}
//
//
//
//
