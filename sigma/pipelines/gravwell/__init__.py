from .gravwell import gravwell_windows_pipeline, gravwell_windows_sysmon_acceleration_keywords, gravwell_cim_data_model

pipelines = {
    "gravwell_windows": gravwell_windows_pipeline,
    "gravwell_sysmon_acceleration": gravwell_windows_sysmon_acceleration_keywords,
    "gravwell_cim": gravwell_cim_data_model,
}