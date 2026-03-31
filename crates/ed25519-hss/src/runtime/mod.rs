pub mod prime_order_cpu_executor;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use prime_order_cpu_executor::{
    compile_default_prime_order_cpu_execution_program, compile_prime_order_cpu_execution_program,
    default_prime_order_cpu_executor_benchmark_config, execute_prime_order_cpu_execution_program,
    generate_prime_order_cpu_executor_benchmark_report, PrimeOrderCpuExecutionProgram,
    PrimeOrderCpuExecutionResult, PrimeOrderCpuExecutionStep, PrimeOrderCpuExecutorBenchmarkConfig,
    PrimeOrderCpuExecutorBenchmarkReport, PRIME_ORDER_CPU_EXECUTOR_BENCHMARK_REPORT_VERSION,
};
