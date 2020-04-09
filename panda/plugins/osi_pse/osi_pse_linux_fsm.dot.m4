digraph finite_state_machine {
	rankdir=LR;
	size="9,6"

	define(`base_node',`fontname=Courier, fontsize=13, fixedsize=true, width=1.2, height=1.2')
	define(`end_node',`shape=doublecircle, base_node')
	define(`inner_node', `shape=circle, base_node')
	define(`trans_node', `shape=point, width=0.0, height=0.0, label=""')
	define(`err_node',`style=filled, fillcolor=red, fontcolor=white')

	define(`base_edge', `fontname=Courier, fontsize=10, splines=true')
	define(`dashed_edge', `style=dashed, base_edge')
	define(`split_edge', `arrowhead=odot, base_edge')

	INIT [end_node];
	KERN [end_node];
	RUN [inner_node];
	ENDG [end_node];
	EXE [inner_node];
	CLN [inner_node];
	VFRK_P [inner_node];
	ERR [end_node, err_node];
	NEW [end_node];

	INIT -> RUN [base_edge, label="sys_start(*)" ];
	INIT -> KERN [base_edge, label="asid == 0xffffffff"];
	RUN -> ENDG [base_edge, label="sys_start(exit_group)"];

	# execve
	RUN -> EXE [base_edge, label="sys_start(execve)"];
	EXE -> EXE [base_edge, label="sys_start(execve)"];
	EXE -> ENDG [base_edge, label="sys_start(exit_group)"];
	EXE -> ERR [base_edge, label="sys_start(~)"];

	# execve - break
	EXE_BRK [trans_node];
	EXE -> EXE_BRK [split_edge, label="sys_start(brk)"];
	EXE_BRK -> ENDG [base_edge];
	EXE_BRK -> NEW [dashed_edge];

	# clone
	RUN -> CLN [base_edge, label="sys_start(clone)"];
	CLN_NEWASID [trans_node];
	CLN -> CLN_NEWASID [split_edge, label="asid_new == unknown"];
	CLN_NEWASID -> RUN [base_edge];
	CLN_NEWASID -> NEW [dashed_edge];

	# vfork
	RUN_VFRK [trans_node];
	RUN -> RUN_VFRK [base_edge, label="sys_start(vfork)"];
	RUN_VFRK -> NEW [dashed_edge]
	RUN_VFRK -> VFRK_P [base_edge]

	#VFRK -> EXE [base_edge, label="sys_start(execve)"];
	#VFRK -> ERR [base_edge, label="sys_start(~)"];

	#RUN -> SIG [base_edge, label="sys_start(kill)"];
	ENDG -> RUN [base_edge, label="sys_start(*) && pid_changed()"];

}

# map callbacks to specific transitions
# vim: ft=dot :
