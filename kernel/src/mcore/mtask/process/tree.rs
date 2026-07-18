use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use conquer_once::spin::OnceCell;
use spin::{RwLock, RwLockReadGuard};

use crate::mcore::mtask::process::{Process, ProcessId};
static PROCESS_TREE: OnceCell<RwLock<ProcessTree>> = OnceCell::uninit();

pub fn process_tree() -> &'static RwLock<ProcessTree> {
    PROCESS_TREE.get_or_init(|| {
        RwLock::new(ProcessTree {
            children: BTreeMap::default(),
            processes: BTreeMap::default(),
        })
    })
}

pub struct ProcessTree {
    pub children: BTreeMap<ProcessId, Vec<Arc<Process>>>,
    pub processes: BTreeMap<ProcessId, Arc<Process>>,
}

pub struct Children<'a> {
    guard: RwLockReadGuard<'a, ProcessTree>,
    pid: ProcessId,
}

impl Children<'_> {
    #[must_use]
    pub fn get(&self) -> Option<impl Iterator<Item = &Arc<Process>>> {
        self.guard.children.get(&self.pid).map(|x| x.iter())
    }
}

impl Process {
    pub(crate) fn publish_child(&self, child: Arc<Process>) {
        let mut tree = process_tree().write();
        assert!(
            tree.processes.insert(child.pid(), child.clone()).is_none(),
            "child process published twice"
        );
        tree.children.entry(self.pid()).or_default().push(child);
    }

    #[allow(clippy::missing_panics_doc)] // this panic must not happen, so the caller shouldn't have to care about it
    pub fn parent(&self) -> Arc<Process> {
        process_tree()
            .read()
            .processes
            .get(&*self.ppid.read())
            .expect("parent process not found")
            .clone()
    }

    pub fn children(&self) -> Children<'_> {
        let guard = process_tree().read();
        Children {
            guard,
            pid: self.pid,
        }
    }
}
