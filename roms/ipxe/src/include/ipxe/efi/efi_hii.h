#ifndef _IPXE_EFI_HII_H
#define _IPXE_EFI_HII_H

/** @file
 *
 * EFI human interface infrastructure
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <ipxe/efi/Uefi/UefiInternalFormRepresentation.h>
#include <ipxe/efi/Guid/MdeModuleHii.h>

/**
 * Define an EFI IFR form set type
 *
 * @v num_class_guids	Number of class GUIDs
 * @ret type		Form set type
 */
#define EFI_IFR_FORM_SET_TYPE( num_class_guids )			   \
	struct {							   \
		EFI_IFR_FORM_SET FormSet;				   \
		EFI_GUID ClassGuid[num_class_guids];			   \
	} __attribute__ (( packed ))

/**
 * Define an EFI IFR form set
 *
 * @v guid		GUID
 * @v title		Title string
 * @v help		Help string
 * @v type		Form set type (as returned by EFI_IFR_FORM_SET_TYPE())
 * @ret ifr		Form set
 *
 * This definition opens a new scope, which must be closed by an
 * EFI_IFR_END().
 */
#define EFI_IFR_FORM_SET( guid, title, help, type, ... ) {		   \
	.FormSet = {							   \
		.Header = {						   \
			.OpCode = EFI_IFR_FORM_SET_OP,			   \
			.Length = sizeof ( type ),			   \
			.Scope = 1,					   \
		},							   \
		.Guid = guid,						   \
		.FormSetTitle = title,					   \
		.Help = help,						   \
		.Flags = ( sizeof ( ( ( type * ) NULL )->ClassGuid ) /	   \
			   sizeof ( ( ( type * ) NULL )->ClassGuid[0] ) ), \
	},								   \
	.ClassGuid = {							   \
		__VA_ARGS__						   \
	},								   \
	}

/**
 * Define an EFI IFR GUID class
 *
 * @v class		Class
 * @ret ifr		GUID class
 */
#define EFI_IFR_GUID_CLASS( class ) {					   \
	.Header = {							   \
		.OpCode = EFI_IFR_GUID_OP,				   \
		.Length = sizeof ( EFI_IFR_GUID_CLASS ),		   \
	},								   \
	.Guid = EFI_IFR_TIANO_GUID,					   \
	.ExtendOpCode = EFI_IFR_EXTEND_OP_CLASS,			   \
	.Class = class,							   \
	}

/**
 * Define an EFI IFR GUID subclass
 *
 * @v subclass		Subclass
 * @ret ifr		GUID subclass
 */
#define EFI_IFR_GUID_SUBCLASS( subclass ) {				   \
	.Header = {							   \
		.OpCode = EFI_IFR_GUID_OP,				   \
		.Length = sizeof ( EFI_IFR_GUID_SUBCLASS ),		   \
	},								   \
	.Guid = EFI_IFR_TIANO_GUID,					   \
	.ExtendOpCode = EFI_IFR_EXTEND_OP_SUBCLASS,			   \
	.SubClass = subclass,						   \
	}

/**
 * Define an EFI IFR form
 *
 * @v formid		Form ID
 * @v title		Title string
 * @ret ifr		Form
 *
 * This definition opens a new scope, which must be closed by an
 * EFI_IFR_END().
 */
#define EFI_IFR_FORM( formid, title ) {					   \
	.Header = {							   \
		.OpCode = EFI_IFR_FORM_OP,				   \
		.Length = sizeof ( EFI_IFR_FORM ),			   \
		.Scope = 1,						   \
	},								   \
	.FormId = formid,						   \
	.FormTitle = title,						   \
	}

/**
 * Define an EFI IFR text widget
 *
 * @v prompt		Prompt string
 * @v help		Help string
 * @v text		Text string
 * @ret ifr		Text widget
 */
#define EFI_IFR_TEXT( prompt, help, text ) {				   \
	.Header = {							   \
		.OpCode = EFI_IFR_TEXT_OP,				   \
		.Length = sizeof ( EFI_IFR_TEXT ),			   \
	},								   \
	.Statement = {							   \
		.Prompt = prompt,					   \
		.Help = help,						   \
	},								   \
	.TextTwo = text,						   \
	}

/**
 * Define an EFI IFR end marker
 *
 * @ret ifr		End marker
 */
#define EFI_IFR_END() {							   \
	.Header = {							   \
		.OpCode = EFI_IFR_END_OP,				   \
		.Length = sizeof ( EFI_IFR_END ),			   \
	},								   \
	}

#endif /* _IPXE_EFI_HII_H */
