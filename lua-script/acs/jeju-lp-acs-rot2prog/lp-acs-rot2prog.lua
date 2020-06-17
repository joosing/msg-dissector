

local jejuLpAcsProto = Proto("rot2", "rot2")

local tvbs = {}


-- common
startFlag = ProtoField.uint8("rot2.start", "Start Flag", base.HEX )
endFlag = ProtoField.uint8("rot2.end", "End Flag", base.HEX )
pulseVertical = ProtoField.uint8("rot2.pv", "Degree/Pulse(Vertical)", base.HEX, {[0x01]=1,[0x2]=0.5,[0x4]=0.24,[0x0A]=0.1})
pulseHorisontal = ProtoField.uint8("rot2.ph", "Degree/Pulse(Horisontal)", base.HEX, {[0x01]=1,[0x2]=0.5,[0x4]=0.24,[0x0A]=0.1})

-- command
cmdAz = ProtoField.float("rot2.cmdAz", "Commanded Azimuth", base.DEC )
cmdEl = ProtoField.float("rot2.cmdEl", "Commanded Elevation", base.DEC )
cmdType = ProtoField.uint8("rot2.cmdType", "Command Type", base.HEX, {[0x0F]="STOP",[0x1F]="STATUS",[0x2F]="SET"})

-- status 
actAz = ProtoField.float("rot2.actAz", "Actual Azimuth", base.DEC )
actEl = ProtoField.float("rot2.actEl", "Actual Elevation", base.DEC )

local cmdTreeView = 
{
    startFlag,
    cmdAz,
    pulseVertical,
    cmdEl,
    pulseHorisontal,
    cmdType,
    endFlag,
}

local respTreeView = 
{
    startFlag,
    actAz,
    pulseVertical,
    actEl,
    pulseHorisontal,
    endFlag,
}

local rot2Items =
{ 
    startFlag= startFlag,
    endFlag = endFlag,
    pulseVertical = pulseVertical,
    pulseHorisontal = pulseHorisontal,
    cmdAz = cmdAz,
    cmdEl = cmdEl,
    actAz = actAz,
    actEl = actEl,
    cmdType = cmdType,
}

jejuLpAcsProto.fields = rot2Items

function jejuLpAcsProto.init()
    tvbs = {}
end

function jejuLpAcsProto.dissector(buffer, packetInfo, detailTreeView)

    tvbs = {}

    local pktlen = buffer:len()
    local fields = { }

    -- 중요! tvb 인덱스는 0부터 / LUA 배열은 인덱스 1부터 
    topTreeView = detailTreeView:add(jejuLpAcsProto, buffer(0,pktlen)) 

    split(buffer(0,pktlen), fields)

     if pktlen == 12 then
        
        for i, token in ipairs(fields) do
            topTreeView:add(respTreeView[i], buffer:range(token.start,token.len), token.value)
        end    

    elseif pktlen == 13 then
        
        for i, token in ipairs(fields) do
            topTreeView:add(cmdTreeView[i], buffer:range(token.start,token.len), token.value)
        end    
    end

    return pktlen
end

function split(data, fields)

    if data:len() == 12 then -- rx status

        fields[1] = { value = data(0,1):uint(), start = 0, len = 1 }
        fields[2] = { value = ( (data(1,1):uint()*100) + (data(2,1):uint()*10) + data(3,1):uint() + (data(4,1):uint()/10) ) - 360, start = 1, len = 4 }
        fields[3] = { value = data(5,1):uint(), start = 5, len = 1 }
        fields[4] = { value = ( (data(6,1):uint()*100) + (data(7,1):uint()*10) + data(8,1):uint() + (data(9,1):uint()/10) ) - 360, start = 6, len = 4 }
        fields[5] = { value = data(10,1):uint(), start = 10, len = 1 }
        fields[6] = { value = data(11,1):uint(), start = 11, len = 1 }

    elseif data:len() == 13 then -- tx cmd
        fields[1] = { value = data(0,1):uint(), start = 0, len = 1 }
        fields[2] = { value = ( ( ((data(1,1):uint()-0x30)*1000) + ((data(2,1):uint()-0x30)*100) + ((data(3,1):uint()-0x30)*10) + (data(4,1):uint()-0x30) ) / data(5,1):uint() ) - 360, start = 1, len = 4 }
        fields[3] = { value = data(5,1):uint(), start = 5, len = 1 }
        fields[4] = { value = ( ( ((data(6,1):uint()-0x30)*1000) + ((data(7,1):uint()-0x30)*100) + ((data(8,1):uint()-0x30)*10) + (data(9,1):uint()-0x30) ) / data(10,1):uint() ) - 360, start = 6, len = 4 }
        fields[5] = { value = data(10,1):uint(), start = 10, len = 1 }
        fields[6] = { value = data(11,1):uint(), start = 11, len = 1 }
        fields[7] = { value = data(12,1):uint(), start = 12, len = 1 }

    else 
        -- not defined
    end

end

local function enableDissector()
    DissectorTable.get("tcp.port"):add(23, jejuLpAcsProto)
end

enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(23, jejuLpAcsProto)
end
