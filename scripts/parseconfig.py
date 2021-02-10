import os
import re
from glob import glob
from typing import List, Any, Tuple
from dataclasses import dataclass


os.walk(".", topdown=True, followlinks=False)

header = """package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
)

var emptyString = []byte(`""`)
"""


def get_field_name(name: str) -> str:
    field_name_items = name.replace("-", " ")
    field_name_items = field_name_items.replace("_", " ")
    field_name_items = field_name_items.replace(".", " ")
    field_name_items = [x.capitalize() for x in field_name_items.split(" ")]
    field_name = "".join(field_name_items)
    field_name = re.sub(r"^6", "Six", field_name)
    return field_name


def print_unmarshal_type(child_type):
    print(
        f"\nfunc (e *{child_type}) UnmarshalJSON(b []byte) error {{\n"
        f"	if bytes.Equal(b, emptyString) {{\n"
        f"		*e = {child_type}{{}}\n"
        f"		return nil\n"
        f"	}}\n"
        f"	type t {child_type}\n"
        f"	if err := json.Unmarshal(b, (*t)(e)); err != nil {{\n"
        f"		return fmt.Errorf(\"failed to parse nested structure: %w\", err)\n"
        f"	}}\n"
        f"	return nil\n"
        f"}}\n"
    )


def get_field_type(path: str, name: str) -> str:
    node_def = f"{path}/node.def"
    multi: bool = False
    defined_type: str = ""

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


@dataclass()
class Node:
    head: str
    tail: str
    prefix: str
    path: str


def get_nodes(cur_node: Node) -> List[str]:
    # head = cur_node.head
    # tail = cur_node.tail
    # prefix = cur_node.prefix
    # path = cur_node.head
    # head: str, tail: str, prefix: str, path: str) -> List[Any]:
    nodes: List[str] = []
    child_types: List[str] = []
    children = os.listdir(cur_node.path)
    nested_children = []

    print(cur_node.head)
    for child in children:
        field_name = get_field_name(child)
        if os.path.isdir(cur_node.path + "/" + child + "/node.tag"):
            print(
                f"""{field_name} *map[string]{cur_node.prefix}{field_name} `json:"{child},omitempty"`"""
            )
            nested_children.append(
                Node(
                    path=f"{cur_node.path}/{child}/node.tag/",
                    head=f"\ntype {cur_node.prefix}{field_name} struct{{",
                    tail="}",
                    prefix=f"{cur_node.prefix}{field_name}",
                )
            )
            child_types.append(f"{cur_node.prefix}{field_name}")
        elif (
            os.path.isdir(cur_node.path + "/" + child)
            and len(glob(cur_node.path + "/" + child + "/*/")) > 0
        ):
            print(
                f"""{field_name} *{cur_node.prefix}{field_name} `json:"{child},omitempty"`"""
            )
            nested_children.append(
                Node(
                    path=f"{cur_node.path}/{child}/",
                    head=f"\ntype {cur_node.prefix}{field_name} struct{{",
                    tail="}",
                    prefix=f"{cur_node.prefix}{field_name}",
                )
            )
        elif os.path.isdir(cur_node.path + "/" + child):
            field_type = get_field_type(f"{cur_node.path}/{child}/", child)
            print(f"""{field_name} {field_type} `json:"{child},omitempty"`""")

    print(cur_node.tail)

    for node in nested_children:
        child_types += get_nodes(node)

    return child_types


def get_first_nodes(path: str):
    nodes: List[str] = []
    child_types: List[str] = []
    children = [x.split("/")[-2] for x in glob(path + "*/")]
    for child in children:
        if len(glob(path + "/" + child + "/")) > 0:
            field_name = get_field_name(child)
            nodes.append(
                f"""{field_name} *Config{field_name} `json:"{child},omitempty"`"""
            )
            child_types.append(f"Config{field_name}")
            next_node = Node(
                head=f"\ntype Config{field_name} struct{{",
                tail="}",
                prefix=f"Config{field_name}",
                path=f"{path}/{child}/",
            )
            child_types += get_nodes(next_node)

    print("\ntype Config struct {")
    for node in nodes:
        print(node)
    print("}")

    for child_type in child_types:
        print_unmarshal_type(child_type)


if __name__ == "__main__":
    print(header)
    get_first_nodes("./")
