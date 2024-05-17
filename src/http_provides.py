# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""HTTP Provides module."""

import json
from typing import List, Optional, Union

import ops


class HttpProvides:
    """Provides side of the http interface."""

    def __init__(self, parent: ops.CharmBase, relation: str):
        self.model = parent.model
        self.relation_name = relation

    @property
    def relations(self) -> List[ops.Relation]:
        """All the relations using this provider."""
        return self.model.relations.get(self.relation_name) or []

    def get_ingress_address(
        self, relation: ops.Relation = None
    ) -> Optional[Union[str, List[str]]]:
        """Resolve the ingress address from the relation.

        If no relation is provided, we fallback to the first one
        """
        if relation is None:
            relation = self.relations[0]
        unit_data = relation.data[self.model.unit]
        return unit_data.get("ingress-address") or unit_data.get("private-address")

    def configure(self, port, private_address=None, hostname=None):
        """Configure the address(es).

        Private_address and hostname can be None, a single string address/hostname,
        or a list of addresses and hostnames. Note that if a list is passed,
        it is assumed both private_address and hostname are either lists or None
        """
        for relation in self.relations:
            ingress_address = self.get_ingress_address(relation)
            if isinstance(private_address, list) or isinstance(hostname, list):
                # build 3 lists to zip together that are the same length
                length = max(len(private_address), len(hostname))
                p = [port] * length
                a = private_address + [ingress_address] * (length - len(private_address))
                h = hostname + [ingress_address] * (length - len(hostname))
                zipped_list = zip(p, a, h)
                # now build an array of dictionaries from that in the desired
                # format for the interface
                data_list = [
                    {"hostname": h, "port": p, "private-address": a} for p, a, h in zipped_list
                ]
                # for backwards compatibility, we just send a single entry
                # and have an array of dictionaries in a field of that
                # entry for the other entries.
                data = data_list.pop(0)
                data["extended_data"] = json.dumps(data_list)

                relation.data[self.model.unit].update(data)
            else:
                relation.data[self.model.unit].update(
                    {
                        "hostname": hostname or ingress_address,
                        "private-address": private_address or ingress_address,
                        "port": str(port),
                    }
                )
