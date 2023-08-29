import pytest
from sigma.collection import SigmaCollection
from sigma.backends.gravwell import GravwellBackend
from sigma.pipelines.gravwell import gravwell_windows_pipeline, gravwell_windows_sysmon_acceleration_keywords, gravwell_cim_data_model
from sigma.pipelines.common import windows_logsource_mapping
from sigma.exceptions import SigmaTransformationError

@pytest.mark.parametrize(
    ("service", "source"),
    windows_logsource_mapping.items()
)
def test_gravwell_windows_pipeline_simple(service, source):
    if isinstance(source, str):
        assert GravwellBackend(processing_pipeline=gravwell_windows_pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    product: windows
                    service: {service}
                detection:
                    sel:
                        EventID: 123
                        field: value
                    condition: sel
            """)
        ) == [f"source=\"WinEventLog:{source}\" EventCode=123 field=\"value\""]
    else:
        assert GravwellBackend(processing_pipeline=gravwell_windows_pipeline()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    product: windows
                    service: {service}
                detection:
                    sel:
                        EventID: 123
                        field: value
                    condition: sel
            """)
        ) == ["source IN (" + ", ".join((
                f"\"WinEventLog:{source_item}\""
                for source_item in source
            )) + ") EventCode=123 field=\"value\""]

def test_gravwell_sysmon_process_creation_keyword_acceleration():
    assert GravwellBackend(processing_pipeline=gravwell_windows_pipeline() + gravwell_windows_sysmon_acceleration_keywords()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                service: sysmon
                category: process_creation
            detection:
                sel:
                    field: value
                condition: sel
        """)
    )[0].startswith('"ParentProcessGuid"')

def test_gravwell_sysmon_file_creation_keyword_acceleration():
    assert GravwellBackend(processing_pipeline=gravwell_windows_pipeline() + gravwell_windows_sysmon_acceleration_keywords()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                product: windows
                service: sysmon
                category: file_event
            detection:
                sel:
                    field: value
                condition: sel
        """)
    )[0].startswith('"TargetFilename"')

def test_gravwell_process_creation_dm():
    assert GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: test
                    CurrentDirectory: test
                    Image: test
                    IntegrityLevel: test
                    OriginalFileName: test
                    ParentCommandLine: test
                    ParentImage: test
                    ParentProcessGuid: test
                    ParentProcessId: test
                    ProcessGuid: test
                    ProcessId: test
                    User: test
                condition: sel
        """)
    ) == [f"Processes.process=\"test\" Processes.process_current_directory=\"test\" Processes.process_path=\"test\" Processes.process_integrity_level=\"test\" Processes.original_file_name=\"test\" Processes.parent_process=\"test\" Processes.parent_process_path=\"test\" Processes.parent_process_guid=\"test\" Processes.parent_process_id=\"test\" Processes.process_guid=\"test\" Processes.process_id=\"test\" Processes.user=\"test\""]

def test_gravwell_process_creation_dm_unsupported_fields():
    with pytest.raises(SigmaTransformationError):
        GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        imphash: 123456
                    condition: sel
            """)
        )

def test_gravwell_registry_add_dm():
    assert GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: registry_add
                product: windows
            detection:
                sel:
                    Computer: test
                    Details: test
                    EventType: test
                    Image: test
                    ProcessGuid: test
                    ProcessId: test
                    TargetObject: test
                condition: sel
        """)
    ) == [f"""Registry.dest=\"test\" Registry.registry_value_data=\"test\" Registry.action=\"test\"
Registry.process_path=\"test\" Registry.process_guid=\"test\" Registry.process_id=\"test\"
Registry.registry_key_name=\"test\"""".replace("\n", " ")]

def test_gravwell_registry_delete_dm():
    assert GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: registry_delete
                product: windows
            detection:
                sel:
                    Computer: test
                    Details: test
                    EventType: test
                    Image: test
                    ProcessGuid: test
                    ProcessId: test
                    TargetObject: test
                condition: sel
        """)
    ) == [f"""Registry.dest=\"test\" Registry.registry_value_data=\"test\" Registry.action=\"test\"
Registry.process_path=\"test\" Registry.process_guid=\"test\" Registry.process_id=\"test\"
Registry.registry_key_name=\"test\"""".replace("\n", " ")]

def test_gravwell_registry_event_dm():
    assert GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: registry_event
                product: windows
            detection:
                sel:
                    Computer: test
                    Details: test
                    EventType: test
                    Image: test
                    ProcessGuid: test
                    ProcessId: test
                    TargetObject: test
                condition: sel
        """)
    ) == [f"""Registry.dest=\"test\" Registry.registry_value_data=\"test\" Registry.action=\"test\"
Registry.process_path=\"test\" Registry.process_guid=\"test\" Registry.process_id=\"test\"
Registry.registry_key_name=\"test\"""".replace("\n", " ")]

def test_gravwell_registry_set_dm():
    assert GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: registry_set
                product: windows
            detection:
                sel:
                    Computer: test
                    Details: test
                    EventType: test
                    Image: test
                    ProcessGuid: test
                    ProcessId: test
                    TargetObject: test
                condition: sel
        """)
    ) == [f"""Registry.dest=\"test\" Registry.registry_value_data=\"test\" Registry.action=\"test\"
Registry.process_path=\"test\" Registry.process_guid=\"test\" Registry.process_id=\"test\"
Registry.registry_key_name=\"test\"""".replace("\n", " ")]

def test_gravwell_registry_dm_unsupported_fields():
    with pytest.raises(SigmaTransformationError):
        GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    category: registry_add
                    product: windows
                detection:
                    sel:
                        NewName: test
                    condition: sel
            """)
        )

def test_gravwell_file_event_dm():
    assert GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: file_event
                product: windows
            detection:
                sel:
                    Computer: test
                    CreationUtcTime: test
                    Image: test
                    ProcessGuid: test
                    ProcessId: test
                    TargetFilename: test
                condition: sel
        """)
    ) == [f"""Filesystem.dest=\"test\" Filesystem.file_create_time=\"test\" Filesystem.process_path=\"test\"
Filesystem.process_guid=\"test\" Filesystem.process_id=\"test\" Filesystem.file_path=\"test\"""".replace("\n", " ")]

def test_gravwell_file_event_dm_unsupported_fields():
    with pytest.raises(SigmaTransformationError):
        GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    category: file_event
                    product: windows
                detection:
                    sel:
                        field: test
                    condition: sel
            """)
        )

def test_gravwell_dm_unsupported_logsource():
    with pytest.raises(SigmaTransformationError):
        GravwellBackend(processing_pipeline=gravwell_cim_data_model()).convert(
            SigmaCollection.from_yaml(f"""
                title: Test
                status: test
                logsource:
                    category: image_load
                    product: windows
                detection:
                    sel:
                        Image: test
                    condition: sel
            """)
        )
