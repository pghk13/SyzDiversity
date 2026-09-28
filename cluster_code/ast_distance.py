"""AST schema and weighted ordered-tree distance used by the partitioning pipeline."""

DEFAULT_SYSCALL_COST = 5


def process_program_ast(program):
    if "nodes" in program:
        node_depths(program["nodes"], program["adj"])
        return program["nodes"], program["adj"]

    nodes, adj = ["ProgramAST"], [[]]

    def add(parent, label):
        index = len(nodes)
        nodes.append(label)
        adj.append([])
        adj[parent].append(index)
        return index

    def argument(parent, arg, image=False):
        kind = arg.get("type", "UnknownType")
        value = arg.get("value", "")
        label = kind
        if image or kind.startswith("*prog.PointerArg") or value in ("AUTO", "ANY"):
            label += ": ANY"
        elif not kind.startswith("*prog.GroupArg") and isinstance(value, (int, str)):
            label += f": {value}"
        index = add(parent, label)
        if not image:
            for child in arg.get("sub_args", []):
                argument(index, child)

    for call in program.get("calls", []):
        name = call["name"]
        parent = add(0, name)
        args = call.get("args", [])
        for index, arg in enumerate(args):
            image = (name.startswith("syz_mount_image$") or name == "syz_read_part_table") and index == len(args) - 1
            argument(parent, arg, image=image)
    return nodes, adj


def node_depths(nodes, adj):
    if len(nodes) != len(adj):
        raise ValueError("node and adjacency counts differ")
    if not nodes:
        return []
    depths = [-1] * len(nodes)
    stack = [(0, 0)]
    while stack:
        node, depth = stack.pop()
        if not 0 <= node < len(nodes) or depths[node] != -1:
            raise ValueError("AST is not a rooted ordered tree")
        depths[node] = depth
        stack.extend((child, depth + 1) for child in reversed(adj[node]))
    if -1 in depths:
        raise ValueError("AST contains unreachable nodes")
    return depths


def edit_cost(label, depth, syscall_cost=DEFAULT_SYSCALL_COST):
    if depth == 1:
        return syscall_cost
    if depth > 1 and (label.startswith("*prog.PointerArg:") or label.endswith((": ANY", ": AUTO"))):
        return 0
    return 1


def weighted_nodes(tree, syscall_cost=DEFAULT_SYSCALL_COST):
    if syscall_cost < 1:
        raise ValueError("syscall cost must be positive")
    # Costs belong to node occurrences, not labels: repeated labels can have
    # different depths and must not overwrite one another's costs.
    return [(label, edit_cost(label, depth, syscall_cost))
            for label, depth in zip(tree["nodes"], node_depths(tree["nodes"], tree["adj"]))]


def delta(left, right):
    if left is None:
        return right[1]
    if right is None:
        return left[1]
    if left[0] == right[0] or left[1] == 0 or right[1] == 0:
        return 0
    return max(left[1], right[1])


def tree_distance(left, right, syscall_cost=DEFAULT_SYSCALL_COST):
    from edist.ted import ted

    x, y = weighted_nodes(left, syscall_cost), weighted_nodes(right, syscall_cost)
    if not x or not y:
        return sum(cost for _, cost in x + y)
    return float(ted(x, left["adj"], y, right["adj"], delta=delta))


def tree_similarity(left, right, syscall_cost=DEFAULT_SYSCALL_COST):
    size = max(len(left["nodes"]), len(right["nodes"]))
    return 1.0 if size == 0 else 1.0 - tree_distance(left, right, syscall_cost) / size
