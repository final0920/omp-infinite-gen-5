# 模块分层与审查地图（自动生成）

由 `node tools/ci/module-audit.mjs --report` 生成，不要手改。

## host（critical）

编排层：worker 调度与只读数据路由，允许依赖其他各层

- `source/read_only_data_route.js`
- `source/worker_manager.js` **[关键]**

## platform（critical）

审批门、租约、审计、项目存储、worker 传输、地址与输出契约、共享产物工具

- `source/address_ref.js` **[关键]**
- `source/analysis_artifacts.js` **[关键]**
- `source/approval_gate.js` **[关键]**
- `source/attachment_lease.js` **[关键]**
- `source/audit_history.js` **[关键]**
- `source/code_epoch_map.js`
- `source/diag_log.js` **[关键]**
- `source/engine_error.js` **[关键]**
- `source/history_index.js` **[关键]**
- `source/host_platform.js` **[关键]**
- `source/json_output.js` **[关键]**
- `source/kernel_jobs.js`
- `source/patch_export.js` **[关键]**
- `source/project_store.js` **[关键]**
- `source/remote_execution_store.js` **[关键]**
- `source/result_artifacts.js` **[关键]**
- `source/reverse_runtime.js`
- `source/worker_transport.js` **[关键]**

## engines（critical）

与原生进程/网络/调试器交互的采集与执行层

- `source/capture_ca.js` **[关键]**
- `source/capture_payload.js`
- `source/capture_proxy.js` **[关键]**
- `source/capture_review.js`
- `source/capture_service.js`
- `source/capture_state_trace.js`
- `source/composition_chain.js`
- `source/composition_jobs.js`
- `source/composition_opaque.js`
- `source/debug_timeout.js`
- `source/debug_trace.js` **[关键]**
- `source/debug_trace_chunks.js`
- `source/delivered_payload.js`
- `source/guest_debug_profile.js` **[关键]**
- `source/guest_recovery.js` **[关键]**
- `source/lift_jobs.js`
- `source/native_store_events.js` **[关键]**
- `source/native_trace_encoding.js`
- `source/projection_decoder.js`
- `source/projection_jobs.js`
- `source/projection_opaque.js`
- `source/recorded_flow_eval.js`
- `source/recorded_handler_eval.js`
- `source/recorded_projection_coordinates.js`
- `source/trace_jobs.js`

## analysis（standard）

分析、验证、去混淆与 VM 恢复（以纯计算为主）

- `source/analysis_failure.js`
- `source/analysis_jobs.js`
- `source/analysis_worker.js`
- `source/bitvector_contract.js`
- `source/bitvector_provider.js`
- `source/bitvector_provider_adapter.js`
- `source/bitvector_replay.js`
- `source/bitvector_solver.js`
- `source/candidate_workflow.js`
- `source/cff_overlay.js`
- `source/cff_state.js`
- `source/cff_state_workflow.js`
- `source/cff_workflow.js`
- `source/crypto_analysis.js`
- `source/crypto_recovery.js`
- `source/dashboard_projection.js`
- `source/diagnostic_store.js`
- `source/evidence_adapters/dossier.js`
- `source/evidence_adapters/fixed_properties.js`
- `source/evidence_adapters/vm_context.js`
- `source/evidence_dependencies.js`
- `source/evidence_registry.js`
- `source/experiment_planner.js`
- `source/experiment_shadow.js`
- `source/failure_adapters.js`
- `source/failure_record.js`
- `source/failure_router.js`
- `source/flow_pair_sampling.js`
- `source/flow_semantics_jobs.js`
- `source/flow_state_eval.js`
- `source/function_batches.js` **[关键]**
- `source/function_dossier.js` **[关键]**
- `source/implementation_info.js` **[关键]**
- `source/method_applicability.js`
- `source/method_registry.js`
- `source/obligation_evaluator.js`
- `source/observed_decode_jobs.js`
- `source/path_discovery_jobs.js`
- `source/planning_identity.js`
- `source/planning_runtime.js`
- `source/protocol_analysis.js`
- `source/protocol_inference.js`
- `source/protocol_state.js`
- `source/verification_registry.js`
- `source/verification_result.js`
- `source/verification_schema.js`
- `source/verifier_catalog.js`
- `source/verifiers/vm_context_audit.js`
- `source/verifiers/vm_function_oracle.js`
- `source/verifiers/vm_function_verify.js`
- `source/verifiers/vm_recorded_function.js`
- `source/vm_address_roles.js`
- `source/vm_bytecode.js`
- `source/vm_cfg.js`
- `source/vm_context_model.js`
- `source/vm_context_profile.js`
- `source/vm_fetch_flow.js`
- `source/vm_flow_mapping.js`
- `source/vm_flow_profile.js`
- `source/vm_flow_recurrences.js`
- `source/vm_flow_window.js`
- `source/vm_function_contract.js`
- `source/vm_handler_profile.js`
- `source/vm_handler_window.js`
- `source/vm_instance_workflow.js`
- `source/vm_instances.js`
- `source/vm_observation_profile.js`
- `source/vm_observations.js`
- `source/vm_phase_context.js`
- `source/vm_phase_model.js`
- `source/vm_program.js`
- `source/vm_recovery_case.js`
- `source/vm_recovery_io.js`
- `source/vm_recovery_plan.js`
- `source/vm_recovery_profile.js`
- `source/vm_recurrence_profile.js`
- `source/vm_role_compare.js`
- `source/vm_role_profile.js`
- `source/vm_role_samples.js`
- `source/vm_role_validation.js`

## research（standard）

调查、研究状态、知识库、记忆与委托

- `source/autonomy_status.js`
- `source/capability_acceptance.js`
- `source/capability_catalog.js`
- `source/delegation_control.js`
- `source/investigation_brief.js`
- `source/investigation_planning.js`
- `source/investigation_resume.js`
- `source/investigation_store.js`
- `source/investigation_view.js`
- `source/investigation_workflow.js`
- `source/knowledge_catalog.js`
- `source/knowledge_documents.js`
- `source/knowledge_import.js`
- `source/knowledge_io.js`
- `source/knowledge_publish_v2.js`
- `source/knowledge_seeds.js`
- `source/knowledge_v2.js`
- `source/knowledge_v2_compat.js`
- `source/lcm_bridge.js`
- `source/lcm_memory.js`
- `source/research_case_bridge.js`
- `source/research_case_index.js`
- `source/research_discovery.js`
- `source/research_discovery_review.js`
- `source/research_properties.js`
- `source/research_state.js`
- `source/research_v2_contract.js`
- `source/research_v2_store.js`

## entry（standard）

插件入口与工具装配

- `advanced_tools.js`
- `analysis_tools.js`
- `capture_tools.js` **[关键]**
- `client.js`
- `engine_runtime.js` **[关键]**
- `index.js` **[关键]**
- `integration_tools.js` **[关键]**
- `semantic_diff.js`
- `semantic_diff_async.js`
- `semantic_diff_worker.js`
- `workflow.js` **[关键]**
