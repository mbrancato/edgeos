import os
import re
import sys
from glob import glob
from typing import List, Any, Tuple, Optional
from dataclasses import dataclass, field

os.walk(".", topdown=True, followlinks=False)

sdkHeader = """package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
)

var emptyString = []byte(`""`)
"""

cliHeader = """package sdk

"""


@dataclass
class Node:
    field_name: str
    name: str
    path: str = ""
    type: str = ""
    children: List["Node"] = field(default_factory=list)


def get_field_name(name: str) -> str:
    field_name_items = name.replace("-", " ")
    field_name_items = field_name_items.replace("_", " ")
    field_name_items = field_name_items.replace(".", " ")
    field_name_items = [x.capitalize() for x in field_name_items.split(" ")]
    field_name = "".join(field_name_items)
    field_name = re.sub(r"^6", "Six", field_name)
    return field_name


def get_unmarshal_for_type(node: Node) -> str:

    return f"""
func (e *Config{node.field_name}) UnmarshalJSON(b []byte) error {{
    if bytes.Equal(b, emptyString) {{
        *e = Config{node.field_name}{{}}
        return nil
    }}
    type t Config{node.field_name}
    if err := json.Unmarshal(b, (*t)(e)); err != nil {{
        return fmt.Errorf("failed to parse nested structure: %w", err)
    }}
    return nil
}}
"""


def get_field_type(path: str, name: str) -> str:
    node_def = f"{path}/node.def"
    multi: bool = False

    if os.path.exists(node_def):
        with open(node_def, "r") as f:
            if re.match(r"^multi:", f.read()):
                multi = True
        with open(node_def, "r") as f:
            m = re.match(r"^type:.*", f.read())
            if m:
                type_line = m[0]
            else:
                type_line = "type: txt"

    type_line = type_line.split(";")[0]
    type_line = type_line.split(":")[1]
    type_line = "".join(type_line.split())

    type_map = {
        "txt": "string",
        "bool": "bool",
        "u32": "EdgeOSInt",
        "ipv4": "IPv4",
        "ipv6": "IPv6",
        "ipv4,ipv6": "IP",
        "ipv4net": "IPv4Net",
        "ipv6net": "IPv6Net",
        "ipv4net,ipv6net": "IPNet",
        "ipv6,ipv6net": "IPv6Net",
        "macaddr": "MacAddr",
    }

    defined_type = type_map.get(type_line, "string")
    if multi:
        return "[]" + defined_type
    else:
        return defined_type


def get_simple_type(name: str) -> str:
    type_map = {
        "map": "name",
        "string": "string",
        "bool": "bool",
        "EdgeOSInt": "integer",
        "IPv4": "ipv4",
        "ipIPv6v6": "ipv6",
        "IP": "ip",
        "IPv4Net": "ipv4 network",
        "IPv6Net": "ipv6 network",
        "IPNet": "ip network",
        "MacAddr": "mac addr",
    }

    return type_map.get(name)


def get_nodes(cur_node: Node) -> List[str]:
    children = os.listdir(cur_node.path)

    for child in children:
        field_name = get_field_name(child)
        if os.path.isdir(cur_node.path + "/" + child + "/node.tag"):
            cur_node.children.append(
                Node(
                    path=f"{cur_node.path}/{child}/node.tag/",
                    name=child,
                    field_name=f"{cur_node.field_name}{field_name}",
                    type="map",
                )
            )
        elif (
            os.path.isdir(cur_node.path + "/" + child)
            and len(glob(cur_node.path + "/" + child + "/*/")) > 0
        ):
            cur_node.children.append(
                Node(
                    name=child,
                    field_name=f"{cur_node.field_name}{field_name}",
                    path=f"{cur_node.path}/{child}",
                    type="obj",
                )
            )
        elif os.path.isdir(cur_node.path + "/" + child):
            field_type = get_field_type(f"{cur_node.path}/{child}/", child)

            cur_node.children.append(
                Node(
                    name=child,
                    field_name=f"{cur_node.field_name}{field_name}",
                    path=f"{cur_node.path}/{child}",
                    type=field_type,
                )
            )

    for node in cur_node.children:
        get_nodes(node)


def get_field_config(node: Node) -> str:

    if not node.children and node.type != "map" and node.type != "obj":
        return f"""{get_field_name(node.name)} {node.type} `json:"{node.name},omitempty"`\n"""

    if node.type == "map":
        return f"""{get_field_name(node.name)} *map[string]Config{node.field_name} `json:"{node.name},omitempty"`\n"""

    if node.type == "obj":
        return f"""{get_field_name(node.name)} *Config{node.field_name} `json:"{node.name},omitempty"`\n"""

    raise RuntimeError("Unknown node type and node has children")


def get_config(node: Node) -> str:
    config = f"""type Config{node.field_name} struct {{\n"""
    for child in node.children:
        config += get_field_config(child)
    config += """}\n\n"""

    for child in node.children:
        if child.type in ["obj", "map"]:
            config += get_config(child)

    return config


def get_unmarshal(node: Node) -> str:
    um = ""

    for child in node.children:
        if child.type in ["obj", "map"]:
            um += get_unmarshal_for_type(child)
            um += get_unmarshal(child)

    return um


def get_field_cli(node: Node) -> str:
    if not node.children and node.type != "map" and node.type != "obj":
        res = f"""
        {get_field_name(node.name)} CliField{node.field_name} `cmd:"" name:"{node.name}" aliases:"{get_field_name(node.name)}"`"""

    if node.type == "map":
        res = f"""
        {get_field_name(node.name)} CliMap{node.field_name} `cmd:"" name:"{node.name}" aliases:"{get_field_name(node.name)}"`"""

    if node.type == "obj":
        res = f"""
        {get_field_name(node.name)} Cli{node.field_name} `cmd:"" name:"{node.name}" aliases:"{get_field_name(node.name)}"`"""

    return res


def get_field_cli_types(node: Node) -> str:

    res = ""
    if not node.children and node.type != "map" and node.type != "obj":
        res = f"""
            type CliField{node.field_name} struct {{
                {get_field_name(node.name)} struct {{ 
                    {get_field_name(node.name)} {node.type} `arg:"" name:"{get_simple_type(node.type)}" aliases:"{get_field_name(node.name)}"` 
                }} `arg:"" name:"{get_simple_type(node.type)}"`
            }}
            """

    if node.type == "map":
        res = f"""
            type CliMap{node.field_name} struct {{
                {get_field_name(node.name)} struct {{ 
                    {get_field_name(node.name)} string `arg:"" name:"{get_simple_type(node.type)}"`
                    Cmd{get_field_name(node.name)} Cli{node.field_name} `embed:""`
                }} `arg:"" name:"{get_simple_type(node.type)}"`
            }}
            """

    for child in node.children:
        res += get_field_cli_types(child)

    return res


def get_cli(node: Node) -> str:
    cli = f"""
        type Cli{node.field_name} struct {{
            DefaultCli{node.field_name} struct{{}} `cmd:"" hidden:"" default:"1"`"""
    for child in node.children:
        cli += get_field_cli(child)
    cli += """}\n\n"""

    for child in node.children:
        if child.type in ["obj", "map"]:
            cli += get_cli(child)

    return cli


def main():
    path = sys.argv[1]
    root_node = Node(field_name="", path=path, name="config", type="root")
    get_nodes(root_node)
    config = get_config(root_node)
    um = get_unmarshal(root_node)
    with open("./sdk/config.go", "w") as f:
        f.write(sdkHeader)
        f.write(config)
        f.write(um)

    cli = get_cli(root_node)
    cli_types = get_field_cli_types(root_node)
    with open("./sdk/cli.go", "w") as f:
        f.write(cliHeader)
        f.write(cli)
        f.write(cli_types)


if __name__ == "__main__":
    main()
