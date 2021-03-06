                    Release Notes PN 93000761_D
               Etherios Cloud Connector for Embedded
                            v2.2.0.1 

INTRODUCTION

        Cloud Connector for Embedded is a software development 
        package used to enable a device to exchange information with 
        Device Cloud.  Cloud Connector supports application to device 
        data interaction (messaging), application and device data 
        storage, and remote management of devices.  Devices are 
        associated with Device Cloud through the Internet or other 
        wide area network connections, which allows for communication
        between the device and customer applications, via Device Cloud.

SUPPORTED PRODUCTS

        Etherios Cloud Connector for Embedded

ENHANCEMENTS

    v2.2.0

        Data Point API extended to allow sending data points to multiple 
        different data streams in one message. [IC4C-217]
        The data_point sample application makes use of new API.

    v2.1.0

        Full SMS transport support for Short Messaging (SM) protocol.
        The example implementation is made through Gammu project.

        Device ID autoprovision: a device connecting through EDP protocol
        can ask Device Cloud for an autogenerated Device ID instead of
        providing one.

        Added two new connector_initiate_request_id memebers for canceling
        timed-out SM sessions: connector_initiate_session_cancel and
        connector_initiate_session_cancel_all.

        Data Service / Data Points: status callback is always called
        in both EDP (TCP) and SM (UDP or SMS) either a response is needed
        or not.
        
        Optimization in the SM protocol implementation.
        
        Reduce memory usage when CONNECTOR_MSG_MAX_TRANSACTION is set.
        [IC4C-165]

    v2.0.0

        This is the initial public release and a replacement product 
        for the iDigi Connector for Embedded.  
        
        With respect to iDigi Connector v1.2, Cloud Connector includes 
        optimized Remote Configuration support with significantly 
        smaller memory foot print and reduced network bandwidth usage; 
        Support for Data Streams, and support for Short Messaging over 
        UDP.

BUG FIXES

    v2.2.0

        Linux platform compiles under cygwin environment. [IC4C-302]

    v2.1.0
        
        Fixed known issue in RCI in which a setting was overwritten if
        a setting was set to a string longer than the maximum allowed.
        [IC4C-180]
        
        Completely removed the use of rand() functions. [IC4C-109].
        
        Fixed failure when sending very large Data Streams. [IC4C-287]
        
        Added macro CONNECTOR_SM_MAX_DATA_POINTS_SEGMENTS to allow
        bigger Data Point uploads in SM transports. [IC4C-290]
        
        CLI request was split in different command lines with multipart
        messages. [IC4C-285]
        
        Argument 'maxResponseSize' for CLI over SM (UDP & SMS) did not
        work properly. [IC4C-276]
        
        Connector was aborted when a "Request Connect" was received
        in an application with no TCP transport enabled. [IC4C-274]
        
        UDP transport did not correctly start if the open or send callbacks
        returned connector_callback_busy. [IC4C-241] [IC4C-240]

        CONNECTOR_NETWORK_UDP_START macro was not working. [IC4C-204]
        
    v2.0.1

        Removed rand_r() which is not C89 compliant.  [IC4C-109]

        connector_initiate_action() connector_initiate_data_point_
        binary request over connector_transport_tcp writes incorrect 
        data to Device Cloud.  [IC4C-110]

        Sample project "data_point" in step mode, hangs and throws a 
        core dump.  [IC4C-111]

        SM (/UDP) does not work with IMEI WAN Device IDs.  [IC4C-115]

        Datapoints not working when CONNECTOR_NO_MALLOC defined.  
        [IC4C-116]

        Data point native types for int and long are ambiguous.
        [IC4C-118]

        The connector_callback_unrecognized user return value in SM 
        Cloud request callback is not handled correctly.  [IC4C-119]

        Bad termination of hint on DP4D error.  [IC4C-139]

        Function tcp_receive_packet() does not handle connector_
        callback_error case correctly.  [IC4C-140] [IC4C-159]

        Function edp_tcp_send_process() defaults connector_callback_
        error case for tcp_send_buffer().  [IC4C-140] [IC4C-160]

        Initiate action calls doesn't check if transport is running.
        [IC4C-141]

        Bad handling of ping_response callback returning unrecognized.
        [IC4C-142]

        Data Put from platform over SM/UDP continuously sends target 
        callback.  [IC4C-149]

        Callback returning error is not correctly handled when 
        receiving data from the platform.  [IC4C-151]

        Cloud Connector gives a malformed bRCI command, recovering a 
        big string.  [IC4C-157]

        Cloud Connector gives a malformed bRCI command, setting a 
        big string.  [IC4C-163]          

        Firmware download API no longer provides program size. 
        [IC4C-168]

        Adjusted maximum incoming RCI buffer to CONNECTOR_RCI_
        MAXIMUM_CONTENT_LENGTH define. [IC4C-176] [IC4C-164]

    v2.0.0

        Corrected ARM misalignment warnings, which cause compilation 
        errors due to -Werror.  The casting was between byte and word 
        pointers, which verified safe in the original code.  A cast 
        to void * was used to avoid the warning.  [IC4C-49] 

KNOWN LIMITATIONS

    v2.1.0

        If a Data Point over TCP contains a string that does not fit in a
        single message it will not be sent properly, probably creating a
        Data Stream with no Data Points in it on Device Cloud. The maximum
        value for a string among a Data Point is 497. This does not affect
        SM transports.

    v2.0.1

        When using RCI facility, if a setting value is set to a string 
        longer than CONNECTOR_RCI_MAXIMUM_CONTENT_LENGTH (defined at 
        connector_config.h), the setting is overwritten and the response 
        received has both success and error fields.  [IC4C-180]
    
HISTORY

    v2.1.0

        This release includes SM protocol over SMS support and other SM
        protocol implementation improvements. Additionally, it adds support
        for Device ID autoptovision and improves the behavior of Data 
        Services and Data Point callbacks to facilitate memory management.

    v2.0.0

        This is the initial public release and a replacement product 
        for the iDigi Connector for Embedded.  
        
        With respect to iDigi Connector v1.2, Cloud Connector includes 
        optimized Remote Configuration support with significantly 
        smaller memory foot print and reduced network bandwidth usage; 
        Support for Data Streams, and support for Short Messaging over 
        UDP.

        Corrected ARM misalignment warnings, which cause compilation 
        errors due to -Werror.  The casting was between byte and word 
        pointers, which verified safe in the original code.  A cast 
        to void * was used to avoid the warning.  [IC4C-49] 
