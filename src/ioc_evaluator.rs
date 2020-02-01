use crate::data::{EvaluationPolicy, IocEntryId, IocId};
use std::collections::HashMap;
use crate::data::{IocSearchError, IocSearchResult};
use serde::export::fmt::Display;
use std::fmt::Formatter;

#[derive(Clone)]
pub struct IocEntryItem {
    pub id: IocEntryId,
    pub eval_policy: EvaluationPolicy,
    pub child_eval: EvaluationPolicy,
    pub children: Option<Vec<IocEntryId>>,
}

#[derive(Debug, Clone)]
pub struct IocEntrySearchResult {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub data: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IocEntrySearchError {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub kind: String,
    pub message: String,
}

impl Display for IocEntrySearchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "IocError(ioc_id: {}, kind: {}, message: {})", self.ioc_id, self.kind, self.message)
    }
}

pub struct IocEvaluator {
    root_ioc_ids: HashMap<IocEntryId, IocId>,
    id_ioc_entries: HashMap<IocEntryId, IocEntryItem>,
    id_founds: HashMap<IocEntryId, Result<IocEntrySearchResult, IocEntrySearchError>>,
}

impl IocEvaluator {
    pub fn new(root_ioc_ids: HashMap<IocEntryId, IocId>,
               id_ioc_entries: HashMap<IocEntryId, IocEntryItem>,
               founds: Vec<Result<IocEntrySearchResult, IocEntrySearchError>>,
    ) -> Self {
        let id_founds: HashMap<IocEntryId, Result<IocEntrySearchResult, IocEntrySearchError>> =
            founds.into_iter().map(|result| {
                match result {
                    Ok(result_value) => (result_value.ioc_entry_id.clone(), Ok(result_value)),
                    Err(error) => (error.ioc_entry_id.clone(), Err(error)),
                }
            }).collect();

        IocEvaluator {
            root_ioc_ids,
            id_ioc_entries,
            id_founds,
        }
    }

    pub fn evaluate(&self) -> Vec<IocId> {
        let evaluate_ioc_entries: Vec<IocEntryId> =
            self.id_ioc_entries.iter().filter_map(|(_, ioc_entry)| self.evaluate_one(&ioc_entry)).collect();
        let mut ioc_ids: Vec<IocId> = evaluate_ioc_entries.iter().map(|ioc_entry_id| self.root_ioc_ids.get(ioc_entry_id).unwrap().clone()).collect();
        ioc_ids.sort();
        ioc_ids.dedup();
        ioc_ids
    }

    fn evaluate_one(
        &self,
        ioc_entry: &IocEntryItem,
    ) -> Option<IocEntryId> {
        let evaluated_self = self.evaluate_simple(ioc_entry);
        match evaluated_self {
            None => match ioc_entry.eval_policy {
                EvaluationPolicy::All => return None,
                EvaluationPolicy::One => return self.evaluate_children(&ioc_entry, None)
            }
            Some(ioc_report) => {
                match ioc_entry.eval_policy {
                    EvaluationPolicy::All => return self.evaluate_children(&ioc_entry, evaluated_self),
                    EvaluationPolicy::One => return evaluated_self
                }
            }
        }
    }

    fn evaluate_simple(
        &self,
        ioc_entry: &IocEntryItem,
    ) -> Option<IocEntryId> {
        let report = self.id_founds.get(&ioc_entry.id);
        match report {
            None => None,
            Some(report) => match report {
                Ok(report) => Some(ioc_entry.id),
                Err(_) => None,
            },
        }
    }

    fn evaluate_children(
        &self,
        parent_ioc_entry: &IocEntryItem,
        empty_children_evaluation_result: Option<IocEntryId>,
    ) -> Option<IocEntryId> {
        let children = parent_ioc_entry.children.as_ref();
        match children {
            None => return empty_children_evaluation_result,
            Some(children) => {
                if children.is_empty() {
                    return empty_children_evaluation_result;
                }
                match parent_ioc_entry.child_eval {
                    EvaluationPolicy::All => {
                        let found_children = self.evaluate_non_empty_vector(children);
                        if found_children.len() == children.len() {
                            return Some(children[0]);
                        }
                        return None;
                    }
                    EvaluationPolicy::One => {
                        let found_children = self.evaluate_non_empty_vector(children);
                        if found_children.len() > 0 {
                            return Some(found_children[0].clone());
                        }
                        return None;
                    }
                }
            }
        }
    }

    fn evaluate_non_empty_vector(&self, ioc_entry_ids: &Vec<IocEntryId>) -> Vec<IocEntryId> {
        let found = ioc_entry_ids.iter()
            .filter_map(|ioc_entry_id| {
                let ioc_entry = self.id_ioc_entries.get(ioc_entry_id);
                match ioc_entry {
                    None => None,
                    Some(ioc_entry) => self.evaluate_one(ioc_entry),
                }
            });
        found.collect()
    }
}
