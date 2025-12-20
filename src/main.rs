use std::env;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async move {
        let args: Vec<String> = env::args().collect();
        redoxer::main(&args).await;
    })
}
