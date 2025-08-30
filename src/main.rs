use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    redoxer::main(&args);
}
    let rt = if config.worker_threads > 1 {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder
            .worker_threads(config.worker_threads)
            .max_blocking_threads(config.worker_threads - 1);
        builder
    } else {
        tokio::runtime::Builder::new_current_thread()
    }
    .thread_stack_size(liboui::MIN_REQUIRED_TASK_STACK_SIZE)
    .thread_name(WORKER_THREAD_NAME)
    .enable_io()
    .build()
    .unwrap_or_else(|err| {
        panic!("Failed to create tokio runtime! Error: {:?}", err);
