import numpy as np

def format_repr(class_name: str, fields: dict) -> str:
    """
    Format a class representation professionally, with each parameter on a new line,
    properly indented. Handles nested multi-line representations correctly.
    """
    lines = []
    for key, val in fields.items():
        val_repr = repr(val)
        if "\n" in val_repr:
            # Indent each line of the nested multi-line representation
            val_lines = val_repr.split("\n")
            indented_val = val_lines[0] + "\n" + "\n".join("    " + line for line in val_lines[1:])
            lines.append(f"    {key}={indented_val}")
        else:
            lines.append(f"    {key}={val_repr}")
    return f"{class_name}(\n" + ",\n".join(lines) + "\n)"

def get_config_fields(config_obj) -> dict:
    """
    Dynamically extract the attributes from a config object that correspond to Params fields.
    """
    # Import inside to avoid circular imports
    from enigma2.config.model_params import _E2Params
    
    params = getattr(config_obj, "params", None)
    if params is None:
        return {}
        
    param_fields = list(params.__class__.model_fields.keys())
    
    if hasattr(params, "elements_creation_params") and params.elements_creation_params is not None:
        creation_fields = list(params.elements_creation_params.__class__.model_fields.keys())
    else:
        creation_fields = []
        
    fields = {}
    
    # Check top-level fields
    for field in param_fields:
        if field == "elements_creation_params":
            continue
        if hasattr(config_obj, field):
            fields[field] = getattr(config_obj, field)
            
    # Check elements creation fields
    for field in creation_fields:
        if hasattr(config_obj, field):
            fields[field] = getattr(config_obj, field)
            
    # Include data_compression_alg if present
    if hasattr(config_obj, "data_compression_alg"):
        fields["data_compression_alg"] = getattr(config_obj, "data_compression_alg")
        
    return fields
