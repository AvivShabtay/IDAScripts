def create_user_shared_data_segment():

	result = ida_typeinf.add_til("ntddk_win10", ida_typeinf.ADDTIL_DEFAULT)
	if not result:
		raise Exception("Could not find the type library")

	type_id = ida_typeinf.import_type(None, -1, "KUSER_SHARED_DATA", idaapi.IMPTYPE_OVERRIDE)
	if type_id == idaapi.BADADDR:
		raise Exception("Could not import the type")

	result = ida_segment.add_segm(0, 0x7FFE0000, 0x7FFF0000, "USERDATA", "CONST")
	if not result:
		raise Exception("Could not create segment")

	t = ida_typeinf.tinfo_t()
	result = t.get_named_type(None, "KUSER_SHARED_DATA")
	if not result:
		raise Exception("Could not get type info")

	result = ida_typeinf.apply_tinfo(0x7FFE0000, t, idaapi.TINFO_DEFINITE)
	if not result:
		raise Exception("Could not apply type info for segment")

	result = ida_name.set_name(0x7FFE0000, "userSharedData")
	if not result:
		raise Exception("Could not set name to the structure")
