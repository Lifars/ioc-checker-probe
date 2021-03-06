use crate::data::{EvaluationPolicy, IocEntryId, IocId};
use std::collections::HashMap;

#[derive(Clone)]
pub struct IocEntryItem {
    pub ioc_entry_id: IocEntryId,
    pub ioc_id: IocId,
    pub eval_policy: EvaluationPolicy,
    pub child_eval: EvaluationPolicy,
    pub children: Option<Vec<IocEntryId>>,
    pub checks_specified: u32,
}

#[derive(Debug, Clone)]
pub struct IocEntrySearchResult {
    pub ioc_id: IocId,
    pub ioc_entry_id: IocEntryId,
    pub description: String,
}

pub struct IocEvaluator {
    root_ioc_ids: HashMap<IocId, IocEntryId>,
    id_ioc_entries: HashMap<IocEntryId, IocEntryItem>,
    id_successful_founds_count: HashMap<IocEntryId, u32>,
}

impl IocEvaluator {
    pub fn new(root_ioc_ids: HashMap<IocId, IocEntryId>,
               id_ioc_entries: HashMap<IocEntryId, IocEntryItem>,
               founds: &[IocEntrySearchResult],
    ) -> Self {
        let mut id_successful_founds_count: HashMap<IocEntryId, u32> = HashMap::new();

        for result_value in founds {
            let entry_id = &result_value.ioc_entry_id;
            debug!("Ioc entry {} enumerated", entry_id);
            let success_count = id_successful_founds_count.get(entry_id).cloned();
            match success_count {
                None => {
                    debug!("Ioc entry {} checked 1 time so far", entry_id);
                    id_successful_founds_count.insert(entry_id.clone(), 1);
                }
                Some(success_count) => {
                    debug!("Ioc entry {} checked {} times so far", entry_id, success_count + 1);
                    id_successful_founds_count.insert(entry_id.clone(), success_count + 1);
                }
            }
        };

        IocEvaluator {
            root_ioc_ids,
            id_ioc_entries,
            id_successful_founds_count,
        }
    }

    pub fn evaluate(&self) -> Vec<IocId> {
        let ioc_ids: Vec<IocId> = self.root_ioc_ids.iter()
            .filter(|(ioc_id, ioc_entry_id)| {
                debug!("Evaluating IOC {} with root entry id {}", ioc_id, ioc_entry_id);
                let ioc_entry = self.id_ioc_entries.get(ioc_entry_id);
                let confirmed = self.evaluate_one(ioc_entry.unwrap());
                if confirmed {
                    debug!("IOC {} with root entry id {} confirmed", ioc_id, ioc_entry_id);
                } else {
                    debug!("IOC {} with root entry id {} not confirmed", ioc_id, ioc_entry_id);
                }
                confirmed
            })
            .map(|(ioc_id, _)| ioc_id.clone())
            .collect();
        ioc_ids
    }

    fn evaluate_one(
        &self,
        ioc_entry: &IocEntryItem,
    ) -> bool {
        let evaluated_self = self.evaluate_without_offspring(ioc_entry);
        match evaluated_self {
            false => match ioc_entry.eval_policy {
                EvaluationPolicy::All => if ioc_entry.checks_specified == 0 {
                    self.evaluate_children(&ioc_entry, false)
                } else {
                    false
                },
                EvaluationPolicy::One => self.evaluate_children(&ioc_entry, false)
            }
            true => {
                match ioc_entry.eval_policy {
                    EvaluationPolicy::All => self.evaluate_children(&ioc_entry, true),
                    EvaluationPolicy::One => true
                }
            }
        }
    }

    fn evaluate_without_offspring(
        &self,
        ioc_entry: &IocEntryItem,
    ) -> bool {
        let successful_founds_count = self.id_successful_founds_count.get(&ioc_entry.ioc_entry_id).copied();
        match successful_founds_count {
            None => false,
            Some(successful_founds_count) => match ioc_entry.eval_policy {
                EvaluationPolicy::All => {
                    debug!("Ioc entry {} found {} times out of {}, policy ALL", ioc_entry.ioc_entry_id, successful_founds_count, ioc_entry.checks_specified);
                    successful_founds_count == ioc_entry.checks_specified
                }
                EvaluationPolicy::One => {
                    debug!("Ioc entry {} found {} times out of {}, policy ONE", ioc_entry.ioc_entry_id, successful_founds_count, ioc_entry.checks_specified);
                    successful_founds_count > 0u32
                }
            },
        }
    }

    fn evaluate_children(
        &self,
        parent_ioc_entry: &IocEntryItem,
        empty_children_evaluation_result: bool,
    ) -> bool {
        let children = parent_ioc_entry.children.as_ref();
        match children {
            None => empty_children_evaluation_result,
            Some(children) => {
                if children.is_empty() {
                    empty_children_evaluation_result
                } else {
                    let found_children = self.evaluate_non_empty_vector(children);
                    match parent_ioc_entry.child_eval {
                        EvaluationPolicy::All => {
                            found_children == children.len()
                        }
                        EvaluationPolicy::One => {
                            found_children > 0
                        }
                    }
                }
            }
        }
    }

    fn evaluate_non_empty_vector(&self, ioc_entry_ids: &Vec<IocEntryId>) -> usize {
        let found_count = ioc_entry_ids.iter()
            .filter(|ioc_entry_id| {
                let ioc_entry = self.id_ioc_entries.get(ioc_entry_id);
                match ioc_entry {
                    None => false,
                    Some(ioc_entry) => {
                        self.evaluate_one(ioc_entry)
                    }
                }
            }).count();
        found_count
    }
}
