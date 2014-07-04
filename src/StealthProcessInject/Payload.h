#pragma once

typedef struct
{
	int Length;
	unsigned char Data[64];
} _KeyData;

_KeyData KeyData;

typedef struct
{
	int Length;
	unsigned char Data;
} _PayloadData;