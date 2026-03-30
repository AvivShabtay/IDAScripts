import idaapi
import idautils
import idc
import ida_hexrays
import ida_name


class CallArgPrinter(ida_hexrays.ctree_visitor_t):
    """
    Find all calls to target_ea and print their arguments,
    """
    def __init__(self, cfunc, target_ea):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc     = cfunc
        self.target_ea = target_ea

    def _expr_to_str(self, e):
        """Best-effort convert a cexpr_t to a readable string."""
        if e.op == ida_hexrays.cot_num:
            return f"{e.numval():#x}"
        if e.op == ida_hexrays.cot_var:
            return self.cfunc.lvars[e.v.idx].name
        if e.op == ida_hexrays.cot_obj:
            name = ida_name.get_name(e.obj_ea)
            return name if name else f"{e.obj_ea:#x}"
        if e.op == ida_hexrays.cot_ref:
            return f"&{self._expr_to_str(e.x)}"
        if e.op == ida_hexrays.cot_cast:
            return f"({e.type}) {self._expr_to_str(e.x)}"
        if e.op == ida_hexrays.cot_add:
            return f"{self._expr_to_str(e.x)} + {self._expr_to_str(e.y)}"
        if e.op == ida_hexrays.cot_memptr:
            base = self._expr_to_str(e.x)
            # resolve field name from type
            udt = ida_typeinf.udt_type_data_t()
            if e.x.type.get_pointed_object().get_udt_details(udt):
                for m in udt:
                    if m.offset // 8 == e.m:
                        return f"{base}->{m.name}"
            return f"{base}->[+{e.m}]"
        # fallback: use IDA's own printer
        printer = ida_hexrays.vd_printer_t()
        return str(e.opname)

    def visit_expr(self, e):
        if e.op != ida_hexrays.cot_call:
            return 0
        fn = e.x
        if fn.op != ida_hexrays.cot_obj:
            return 0
        if fn.obj_ea != self.target_ea:
            return 0

        args = [self._expr_to_str(a) for a in e.a]
        print(f"    [{e.ea:#x}]  {ida_name.get_name(self.target_ea)}({', '.join(args)})")
        return 0


def trace_calls(symbol):
    """
    symbol: name string (e.g. 'SymbolName') or integer address
    
    Usage:
        trace_calls('symbol_name')
        trace_calls(symbol_address)
    """
    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays not available.")
        return

    # Resolve symbol to EA
    if isinstance(symbol, str):
        # Try multiple lookup methods
        target_ea = idc.get_name_ea_simple(symbol)
        if target_ea == idc.BADADDR:
            target_ea = ida_name.get_name_ea(idaapi.BADADDR, symbol)
        if target_ea == idc.BADADDR:
            # Fallback: scan all names for a match
            for ea, name in idautils.Names():
                if symbol in name:
                    print(f"[~] '{symbol}' not found directly, using '{name}' at {ea:#x}")
                    target_ea = ea
                    break
        if target_ea == idc.BADADDR:
            print(f"[!] Symbol '{symbol}' not found.")
            return
    else:
        target_ea = symbol

    sym_name = ida_name.get_name(target_ea) or f"{target_ea:#x}"
    print(f"[*] Tracing calls to '{sym_name}' ({target_ea:#x})\n")

    seen_funcs = set()
    total_calls = 0

    for xref in idautils.CodeRefsTo(target_ea, flow=False):
        func = idaapi.get_func(xref)
        if func is None:
            print(f"  [?] {xref:#x} — not inside a known function")
            continue

        func_ea = func.start_ea
        if func_ea in seen_funcs:
            continue
        seen_funcs.add(func_ea)

        func_name = idaapi.get_func_name(func_ea)
        print(f"  [{func_ea:#x}] {func_name}")

        try:
            cfunc = ida_hexrays.decompile(func_ea)
        except Exception as ex:
            print(f"    [!] Decompile failed: {ex}")
            continue
        if cfunc is None:
            print(f"    [!] Decompile returned None")
            continue

        visitor = CallArgPrinter(cfunc, target_ea)
        visitor.apply_to(cfunc.body, None)
        total_calls += 1

    print(f"\n[*] Done — {total_calls} function(s) with calls to '{sym_name}'.")
    