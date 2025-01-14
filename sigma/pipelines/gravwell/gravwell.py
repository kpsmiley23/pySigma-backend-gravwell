from sigma.pipelines.common import \
    logsource_windows, \
    logsource_windows_process_creation, \
    logsource_windows_registry_add, \
    logsource_windows_registry_delete, \
    logsource_windows_registry_event, \
    logsource_windows_registry_set, \
    logsource_windows_file_event, \
    logsource_linux_process_creation, \
    generate_windows_logsource_items
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

windows_sysmon_acceleration_keywords = {    # Map Sysmon event sources and keywords that are added to search for Sysmon optimization pipeline
   "process_creation": "ParentProcessGuid",
   "file_event": "TargetFilename",
}

gravwell_sysmon_process_creation_cim_mapping = {
    "CommandLine": "Processes.process",
    "Computer": "Processes.dest",
    "CurrentDirectory": "Processes.process_current_directory",
    "Image": "Processes.process_path",
    "IntegrityLevel": "Processes.process_integrity_level",
    "OriginalFileName": "Processes.original_file_name",
    "ParentCommandLine": "Processes.parent_process",
    "ParentImage": "Processes.parent_process_path",
    "ParentProcessGuid": "Processes.parent_process_guid",
    "ParentProcessId": "Processes.parent_process_id",
    "ProcessGuid": "Processes.process_guid",
    "ProcessId": "Processes.process_id",
    "User": "Processes.user",
}

gravwell_windows_registry_cim_mapping = {
    "Computer": "Registry.dest",
    "Details": "Registry.registry_value_data",
    "EventType": "Registry.action", # EventType: DeleteKey is parsed to action: deleted
    "Image": "Registry.process_path",
    "ProcessGuid": "Registry.process_guid",
    "ProcessId": "Registry.process_id",
    "TargetObject": "Registry.registry_key_name",
}

gravwell_windows_file_event_cim_mapping = {
    "Computer": "Filesystem.dest",
    "CreationUtcTime": "Filesystem.file_create_time",
    "Image": "Filesystem.process_path",
    "ProcessGuid": "Filesystem.process_guid",
    "ProcessId": "Filesystem.process_id",
    "TargetFilename": "Filesystem.file_path",
}

def gravwell_windows_pipeline():
    return ProcessingPipeline(
        name="Gravwell Windows log source conditions",
        allowed_backends={"gravwell"},
        priority=20,
        items=generate_windows_logsource_items("source", "WinEventLog:{source}") + [
            ProcessingItem(     # Field mappings
                identifier="gravwell_windows_field_mapping",
                transformation=FieldMappingTransformation({
                    "EventID": "EventCode",
                })
            )
        ],
    )

def gravwell_windows_sysmon_acceleration_keywords():
    return ProcessingPipeline(
        name="Gravwell Windows Sysmon search acceleration keywords",
        allowed_backends={"gravwell"},
        priority=25,
        items=[
            ProcessingItem(     # Some optimizations searching for characteristic keyword for specific log sources
                identifier="gravwell_windows_sysmon_process_creation",
                transformation=AddConditionTransformation({
                    None: keyword,
                }),
                rule_conditions=[
                    LogsourceCondition(
                        category=sysmon_category,
                        product="windows",
                        service="sysmon",
                    )
                ]
            )
            for sysmon_category, keyword in windows_sysmon_acceleration_keywords.items()
        ]
    )

def gravwell_cim_data_model():
    return ProcessingPipeline(
        name="Gravwell CIM Data Model Mapping",
        allowed_backends={"gravwell"},
        priority=20,
        items=[
            ProcessingItem(
                identifier="gravwell_dm_mapping_sysmon_process_creation_unsupported_fields",
                transformation=DetectionItemFailureTransformation("The Gravwell Data Model Sigma backend supports only the following fields for process_creation log source: " + ",".join(gravwell_sysmon_process_creation_cim_mapping.keys())),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields = gravwell_sysmon_process_creation_cim_mapping.keys()
                    )
                ]
            ),
            ProcessingItem(
                identifier="gravwell_dm_mapping_sysmon_process_creation",
                transformation=FieldMappingTransformation(gravwell_sysmon_process_creation_cim_mapping),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="gravwell_dm_fields_sysmon_process_creation",
                transformation=SetStateTransformation("fields", gravwell_sysmon_process_creation_cim_mapping.values()),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="gravwell_dm_sysmon_process_creation_data_model_set",
                transformation=SetStateTransformation("data_model_set", "Endpoint.Processes"),
                rule_conditions=[
                    logsource_windows_process_creation(),
                    logsource_linux_process_creation(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="gravwell_dm_mapping_sysmon_registry_unsupported_fields",
                transformation=DetectionItemFailureTransformation("The Gravwell Data Model Sigma backend supports only the following fields for registry log source: " + ",".join(gravwell_windows_registry_cim_mapping.keys())),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields = gravwell_windows_registry_cim_mapping.keys()
                    )
                ]
            ),
            ProcessingItem(
                identifier="gravwell_dm_mapping_sysmon_registry",
                transformation=FieldMappingTransformation(gravwell_windows_registry_cim_mapping),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="gravwell_dm_fields_sysmon_registry",
                transformation=SetStateTransformation("fields", gravwell_windows_registry_cim_mapping.values()),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="gravwell_dm_sysmon_registry_data_model_set",
                transformation=SetStateTransformation("data_model_set", "Endpoint.Registry"),
                rule_conditions=[
                    logsource_windows_registry_add(),
                    logsource_windows_registry_delete(),
                    logsource_windows_registry_event(),
                    logsource_windows_registry_set(),
                ],
                rule_condition_linking=any,
            ),
            ProcessingItem(
                identifier="gravwell_dm_mapping_sysmon_file_event_unsupported_fields",
                transformation=DetectionItemFailureTransformation("The Gravwell Data Model Sigma backend supports only the following fields for file_event log source: " + ",".join(gravwell_windows_file_event_cim_mapping.keys())),
                rule_conditions=[
                    logsource_windows_file_event(),
                ],
                field_name_conditions=[
                    ExcludeFieldCondition(
                        fields = gravwell_windows_file_event_cim_mapping.keys()
                    )
                ]
            ),
            ProcessingItem(
                identifier="gravwell_dm_mapping_sysmon_file_event",
                transformation=FieldMappingTransformation(gravwell_windows_file_event_cim_mapping),
                rule_conditions=[
                    logsource_windows_file_event(),
                ]
            ),
            ProcessingItem(
                identifier="gravwell_dm_fields_sysmon_file_event",
                transformation=SetStateTransformation("fields", gravwell_windows_file_event_cim_mapping.values()),
                rule_conditions=[
                    logsource_windows_file_event(),
                ]
            ),
            ProcessingItem(
                identifier="gravwell_dm_mapping_sysmon_file_event_data_model_set",
                transformation=SetStateTransformation("data_model_set", "Endpoint.Filesystem"),
                rule_conditions=[
                    logsource_windows_file_event(),
                ]
            ),
            ProcessingItem(
                identifier="gravwell_dm_mapping_log_source_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation("Rule type not yet supported by the Gravwell data model CIM pipeline!"),
                rule_condition_negation=True,
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("gravwell_dm_mapping_sysmon_process_creation"),
                    RuleProcessingItemAppliedCondition("gravwell_dm_mapping_sysmon_registry"),
                    RuleProcessingItemAppliedCondition("gravwell_dm_mapping_sysmon_file_event"),
                ],
            ),
        ]
    )

