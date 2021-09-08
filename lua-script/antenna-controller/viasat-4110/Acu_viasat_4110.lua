

local function dialog_func(msg)
    local win = TextWindow.new("Debug");
    win:set(msg)
end


----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings =
{
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 6400, -- default TCP port number for FPM
    max_msg_len  = 168, -- max length of FPM message
    subdissect   = true, -- whether to call sub-dissector or not
    subdiss_type = wtap.NETLINK, -- the encap we get the subdissector for
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            info(table.concat({"Lua: ", ...}," "))  
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()

--------------------------------------------------------------------------------
-- creates a Proto object, but doesn't register it yet
local acuProtocol = Proto("ACU", "ACU")


-- due to a bug in older (prior to 1.12) wireshark versions, we need to keep newly created
-- Tvb's for longer than the duration of the dissect function (see bug 10888)
-- this bug only affects dissectors that create new Tvb's, which is not that common
-- but this FPM dissector happens to do it in order to create the fake SLL header
-- to pass on to the Netlink dissector
local tvbs = {}

---------------------------------------
-- This function will be invoked by Wireshark during initialization, such as
-- at program start and loading a new file
function acuProtocol.init()
    -- reset the save Tvbs
    tvbs = {}
end

-- common
reserved = ProtoField.string("acu.axis.reserved", "reserved", base.ASCII )

-- header 
opcode = ProtoField.string("acu.opcode", "opcode", base.ASCII )

-- "data:10hz"
time10hz = ProtoField.string("acu.10hz.time", "time10hz", base.ASCII )
fault = ProtoField.string("acu.10hz.fault", "fault", base.ASCII )
warning = ProtoField.string("acu.10hz.warning", "warning", base.ASCII )
az_actual = ProtoField.string("acu.10hz.az_actual", "az_act", base.ASCII )
el_actual = ProtoField.string("acu.10hz.el_actual", "el_act", base.ASCII )
az_cmd = ProtoField.string("acu.10hz.az_cmd", "az_cmd", base.ASCII )
el_cmd = ProtoField.string("acu.10hz.el_cmd", "el_cmd", base.ASCII )
az_auto_error = ProtoField.string("acu.10hz.az_auto_error", "az_auto_error", base.ASCII )
el_auto_error = ProtoField.string("acu.10hz.el_auto_error", "el_auto_error", base.ASCII )
tr1_sig = ProtoField.string("acu.10hz.tr1_sig", "tr1_sig", base.ASCII )
tr2_sig = ProtoField.string("acu.10hz.tr2_sig", "tr2_sig", base.ASCII )
tr3_sig = ProtoField.string("acu.10hz.tr3_sig", "tr3_sig", base.ASCII )
tr4_sig = ProtoField.string("acu.10hz.tr4_sig", "tr4_sig", base.ASCII )
select = ProtoField.string("acu.10hz.select", "select", base.ASCII )
scan = ProtoField.string("acu.10hz.scan", "scan", base.ASCII )
virt_ax_mode = ProtoField.string("acu.10hz.virt_ax_mode", "virt_ax_mode", base.ASCII )
virt_el_mode = ProtoField.string("acu.10hz.virt_el_mode", "virt_el_mode", base.ASCII )
virt_az_interlock = ProtoField.string("acu.10hz.virt_az_interlock", "virt_az_interlock", base.ASCII )
virt_el_interlock = ProtoField.string("acu.10hz.virt_el_interlock", "virt_el_interlock", base.ASCII )
slave_alarm = ProtoField.string("acu.10hz.slave_alarm", "slave_alarm", base.ASCII )
rcvr_sel_mode = ProtoField.string("acu.10hz.rcvr_sel_mode", "rcvr_sel_mode", base.ASCII )
at_aug_pending = ProtoField.string("acu.10hz.at_aug_pending", "at_aug_pending", base.ASCII )
at_aug_active = ProtoField.string("acu.10hz.at_aug_active", "at_aug_active", base.ASCII )
tr1_acq_thres = ProtoField.string("acu.10hz.tr1_acq_thres", "tr1_acq_thres", base.ASCII )
tr2_acq_thres = ProtoField.string("acu.10hz.tr2_acq_thres", "tr2_acq_thres", base.ASCII )
tr3_acq_thres = ProtoField.string("acu.10hz.tr3_acq_thres", "tr3_acq_thres", base.ASCII )
tr4_acq_thres = ProtoField.string("acu.10hz.tr4_acq_thres", "tr4_acq_thres", base.ASCII )
slave_cmd_az = ProtoField.string("acu.10hz.slave_cmd_az", "slave_cmd_az", base.ASCII )
slave_cmd_el = ProtoField.string("acu.10hz.slave_cmd_el", "slave_cmd_el", base.ASCII )
rx_pool = ProtoField.string("acu.10hz.rx_pool", "rx_pool", base.ASCII )
pref_rx = ProtoField.string("acu.10hz.pref_rx", "pref_rx", base.ASCII )
earth_off_az = ProtoField.string("acu.10hz.earth_off_az", "earth_off_az", base.ASCII )
earth_off_el = ProtoField.string("acu.10hz.earth_off_el", "earth_off_el", base.ASCII )
az_cmd_sync = ProtoField.string("acu.10hz.az_cmd_sync", "az_cmd_sync", base.ASCII )
el_cmd_sync = ProtoField.string("acu.10hz.el_cmd_sync", "el_cmd_sync", base.ASCII )

-- "data:axis"
azop = ProtoField.string("acu.axis.azop", "azop", base.ASCII )
elop = ProtoField.string("acu.axis.elop", "elop", base.ASCII )
trainop = ProtoField.string("acu.axis.trainop", "trainop", base.ASCII )
time = ProtoField.string("acu.axis.time", "time", base.ASCII )
actual_az = ProtoField.string("acu.axis.az_ped", "az_ped", base.ASCII )
actual_el = ProtoField.string("acu.axis.el_ped", "el_ped", base.ASCII )
actual_train = ProtoField.string("acu.axis.tr_ped", "tr_ped", base.ASCII )
commanded = ProtoField.string("acu.axis.commanded", "commanded", base.ASCII )
offsetfield = ProtoField.string("acu.axis.offset", "offset", base.ASCII )
azmode = ProtoField.string("acu.axis.azmode", "azmode", base.ASCII )
elmode = ProtoField.string("acu.axis.elmode", "elmode", base.ASCII )
trainmode = ProtoField.string("acu.axis.trmode", "trmode", base.ASCII )
upper = ProtoField.string("acu.axis.upper", "upper", base.ASCII )
lower = ProtoField.string("acu.axis.lower", "lower", base.ASCII )
intgerlock = ProtoField.string("acu.axis.intgerlock", "intgerlock", base.ASCII )
velocity = ProtoField.string("acu.axis.velocity", "velocity", base.ASCII )
az_stow_status = ProtoField.string("acu.axis.az_stow_status", "az_stow", base.ASCII )
el_stow_status = ProtoField.string("acu.axis.el_stow_status", "el_stow", base.ASCII )
train_stow_status = ProtoField.string("acu.axis.tr_stow_status", "tr_stow", base.ASCII )
autotrack_stat = ProtoField.string("acu.axis.autotrack_stat", "autotrack_stat", base.ASCII )
slave_cmd = ProtoField.string("acu.axis.slave_cmd", "slave_cmd", base.ASCII )
cablewrap_ang = ProtoField.string("acu.axis.cablewrap_ang", "cablewrap_ang", base.ASCII )
-- "data:axis" analysis
az_mode_analysis = ProtoField.string("az_mode_analysis", "[Az mode toggle]", base.ASCII )


-- data:axis
local acuAzTreeView = 
{
    azop,
    time,
    actual_az,
    commanded,
    offsetfield,
    azmode,
    upper,
    lower,
    intgerlock,
    velocity,
    reserved,
    reserved,
    reserved,
    az_stow_status,
    autotrack_stat,
    slave_cmd,
    reserved,
    cablewrap_ang, -- 18개 필드 
}

local acuElTreeView = 
{
    elop,
    time,
    actual_el,
    commanded,
    offsetfield,
    elmode,
    upper,
    lower,
    intgerlock,
    velocity,
    reserved,
    reserved,
    reserved,
    el_stow_status,
    autotrack_stat,
    slave_cmd,
    reserved,
    cablewrap_ang, -- 18개 필드 
}

local acuTrainTreeView = 
{
    trainop,
    time,
    actual_train,
    commanded,
    offsetfield,
    trainmode,
    upper,
    lower,
    intgerlock,
    velocity,
    reserved,
    reserved,
    reserved,
    train_stow_status,
    autotrack_stat,
    slave_cmd,
    reserved,
    cablewrap_ang, -- 18개 필드 
}

-- data:10hz
local acu10hzTreeView = 
{
    time10hz,
    fault,
    warning,
    az_actual,
    el_actual,
    az_cmd,
    el_cmd,
    az_auto_error,
    el_auto_error,
    tr1_sig,
    tr2_sig,
    tr3_sig,
    tr4_sig,
    reserved,
    reserved,
    select,
    scan,
    virt_ax_mode,
    virt_el_mode,
    virt_az_interlock,
    virt_el_interlock,
    slave_alarm,
    rcvr_sel_mode,
    at_aug_pending,
    at_aug_active,
    tr1_acq_thres,
    tr2_acq_thres,
    tr3_acq_thres,
    tr4_acq_thres,
    reserved,
    reserved,
    slave_cmd_az,
    slave_cmd_el,
    rx_pool,
    pref_rx,
    earth_off_az,
    earth_off_el,
    az_cmd_sync,
    el_cmd_sync,
}

----------------------------------------
-- a table of all of our Protocol's fields
local acuItems =
{ 
    -- common
    reserved = reserved,

    -- analysis
    az_mode_analysis = az_mode_analysis,

    -- opcode 
    opcode = opcode,

    -- data:axis
    azop = azop,
    elop = elop,
    trainop = trainop,
    time = time,
    actual_az = actual_az,
    actual_el = actual_el,
    actual_train = actual_train,
    commanded = commanded,
    offsetfield = offsetfield,
    azmode = azmode,
    elmode = elmode,
    trainmode = trainmode,
    upper = upper,
    lower = lower,
    intgerlock = intgerlock,
    velocity = velocity,
    az_stow_status = az_stow_status,
    el_stow_status = el_stow_status,
    train_stow_status = train_stow_status,
    autotrack_stat = autotrack_stat,
    slave_cmd = slave_cmd,
    cablewrap_ang = cablewrap_ang,

    -- data:10hz
    time10hz = time10hz,
    fault = fault,
    warning = warning,
    az_actual = az_actual,
    el_actual = el_actual,
    az_cmd = az_cmd,
    el_cmd = el_cmd,
    az_auto_error = az_auto_error,
    el_auto_error = el_auto_error,
    tr1_sig = tr1_sig,
    tr2_sig = tr2_sig,
    tr3_sig = tr3_sig,
    tr4_sig = tr4_sig,
    select = select,
    scan = scan,
    virt_ax_mode = virt_ax_mode,
    virt_el_mode = virt_el_mode,
    virt_az_interlock = virt_az_interlock,
    virt_el_interlock = virt_el_interlock,
    slave_alarm = slave_alarm,
    rcvr_sel_mode = rcvr_sel_mode,
    at_aug_pending = at_aug_pending,
    at_aug_active = at_aug_active,
    tr1_acq_thres = tr1_acq_thres,
    tr2_acq_thres = tr2_acq_thres,
    tr3_acq_thres = tr3_acq_thres,
    tr4_acq_thres = tr4_acq_thres,
    slave_cmd_az = slave_cmd_az,
    slave_cmd_el = slave_cmd_el,
    rx_pool = rx_pool,
    pref_rx = pref_rx,
    earth_off_az = earth_off_az,
    earth_off_el = earth_off_el,
    az_cmd_sync = az_cmd_sync,
    el_cmd_sync = el_cmd_sync, 
}


-- register the ProtoItems
acuProtocol.fields = acuItems

--------------------------------------------------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "acuProtocol.dissector = function (buffer,pkt,detailsTreeView)"
-- The 'buffer' is a Tvb object, 'packetInfo' is a Pinfo object, and 'detailsTreeView' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function acuProtocol.dissector(buffer, packetInfo, treeView)

    -- reset the save Tvbs
    tvbs = {}

    -- get the length of the packet buffer (Tvb).
    local pktlen = buffer:len()
    local tokens = { }

    topTreeView = treeView:add(acuProtocol, buffer:range(0,pktlen)) -- 중요! tvb 인덱스는 0부터

    strOpcode = buffer(offset):string():sub(1,9) -- 중요! LUA 배열 인덱스는 1부터
    
    topTreeView:add(opcode, buffer:range(0, 9))

    strParams = buffer(offset):string():sub(11)

    split(strParams, tokens)

    --iAzModeNow = tonumber(tokens[6].t) -- AXIS 모드 값 추출
    --print(iAzModeNow)

    if strOpcode == "data:axis" then
        iAzModeNow = tonumber(tokens[6].t) -- AXIS 모드 값 추출
        print(iAzModeNow)
        strSubOpcode = buffer(offset):string():sub(11,14)
        if strSubOpcode == "axs1" then 
            for i, token in ipairs(tokens) do
                topTreeView:add(acuAzTreeView[i], buffer:range(token.s+10-1,token.l))
            end
        elseif  strSubOpcode == "axs2" then
            for i, token in ipairs(tokens) do
                topTreeView:add(acuElTreeView[i], buffer:range(token.s+10-1,token.l))
            end
        elseif  strSubOpcode == "axs3" then
            for i, token in ipairs(tokens) do
                topTreeView:add(acuTrainTreeView[i], buffer:range(token.s+10-1,token.l))
            end
        end
          


        --topTreeView:add(az_mode_analysis, )

    elseif strOpcode == "data:10hz" then
        
        for i, token in ipairs(tokens) do
            topTreeView:add(acu10hzTreeView[i], buffer:range(token.s+10-1,token.l))
        end
    end

    return pktlen
end

split = function (text, tokens)

    i = 1
    commaIndexList = {}
    commaIndex = 0 
    while true do
        commaIndex = text:find(",", commaIndex+1)    -- find 'next' newline
        if commaIndex == nil then break end
        commaIndexList[i] = commaIndex 
        i = i + 1
    end

    i=1
    start = 1
    len = 0
    for i, commaIndex in ipairs(commaIndexList) do
        token = text:sub(start,commaIndex-1)
        tokens[i] = { t = token, s = start, l = (commaIndex-start)}
        start = commaIndex+1
    end

end


----------------------------------------
-- For us to be able to use Wireshark's built-in Netlink dissector, we have to
-- create a fake SLL layer, which is what this function does.
--
local ARPHRD_NETLINK, WS_NETLINK_ROUTE, emptyBytes

-- in release 1.12+, you could call Tvb:raw() to get the raw bytes, and you
-- can call ByteArray.new() using a Lua string of binary; since that's easier
-- and more efficient, wel;l do that if the Wireshark running this script is
-- 1.12+, otherwise will do the 'else' clause the longer way
if Tvb.raw then
    -- if we're here, this is Wireshark 1.12+, so we can deal with raw Lua binary strings
    
    -- the "hatype" itemView of the SLL must be 824 decimal, in big-endian encoding (0x0338)
    ARPHRD_NETLINK = "\003\056"
    WS_NETLINK_ROUTE = "\000\000"

    emptyBytes = function (num)
        return string.rep("\000", num)
    end

    createSllTvb = function (buffer, begin, length)
        dprint2("FPM createSllTvb function called, using 1.12+ method")
        -- the SLL header and Netlink message
        local sllmsg =
        {
            emptyBytes(2),           -- Unused 2B
            ARPHRD_NETLINK,          -- netlink type
            emptyBytes(10),          -- Unused 10B
            WS_NETLINK_ROUTE,        -- Route type
            buffer:raw(begin, length) -- the Netlink message
        }
        local payload = table.concat(sllmsg)

        return ByteArray.new(payload, true):tvb("Netlink Message")
    end

else
    -- prior to 1.12, the only way to create a ByteArray was from hex-ascii
    -- so we do things in hex-ascii
    ARPHRD_NETLINK = "0338"
    WS_NETLINK_ROUTE = "0000"

    emptyBytes = function (num)
        return string.rep("00", num)
    end

    createSllTvb = function (buffer, begin, length)
        dprint2("FPM createSllTvb function called, using pre-1.12 method")

        -- first get a TvbRange from the Tvb, and the TvbRange's ByteArray...
        local nl_bytearray = buffer(begin,length):bytes()

        -- then create a hex-ascii string of the SLL header portion
        local sllmsg =
        {
            emptyBytes(2),      -- Unused 2B
            ARPHRD_NETLINK,     -- netlink type
            emptyBytes(10),     -- Unused 10B
            WS_NETLINK_ROUTE    -- Route type
        }
        local hexSLL = table.concat(sllmsg)

        -- then create a ByteArray from that hex-string
        local sll_bytearray = ByteArray.new(hexSLL)

        -- then concatenate the two ByteArrays
        local full_bytearray = sll_bytearray .. nl_bytearray

        -- create the new Tvb from the full ByteArray
        -- and because this is pre-1.12, we need to store them longer to
        -- work around bug 10888
        tvbs[#tvbs+1] = full_bytearray:tvb()

        -- now return the newly created Tvb
        return tvbs[#tvbs]
    end
end


--------------------------------------------------------------------------------
-- We want to have our protocol dissection invoked for a specific TCP port,
-- so get the TCP dissector table and add our protocol to it.
local function enableDissector()
    -- using DissectorTable:set() removes existing dissector(s), whereas the
    -- DissectorTable:add() one adds ours before any existing ones, but
    -- leaves the other ones alone, which is better
    DissectorTable.get("tcp.port"):add(6100, acuProtocol)
    DissectorTable.get("tcp.port"):add(6400, acuProtocol)
   
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(6100, acuProtocol)
    DissectorTable.get("tcp.port"):remove(6400, acuProtocol)
end


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences
acuProtocol.prefs.enabled     = Pref.bool("Dissector enabled", default_settings.enabled,
                                        "Whether the FPM dissector is enabled or not")

acuProtocol.prefs.subdissect  = Pref.bool("Enable sub-dissectors", default_settings.subdissect,
                                        "Whether the FPM packet's content" ..
                                        " should be dissected or not")

acuProtocol.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function acuProtocol.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.subdissect  = acuProtocol.prefs.subdissect

    default_settings.debug_level = acuProtocol.prefs.debug
    resetDebugLevel()

    if default_settings.enabled ~= acuProtocol.prefs.enabled then
        default_settings.enabled = acuProtocol.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end

end

dprint2("pcapfile Prefs registered")
