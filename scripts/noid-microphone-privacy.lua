-- NoID Privacy — persistent WirePlumber microphone policy
--
-- When noid.microphone.disabled is true, mute every existing or newly-created
-- Audio/Source node and immediately reverse later unmute attempts. When the
-- setting changes to false, unmute the sources that currently exist once; later
-- user or hardware mute choices remain untouched.

local log = Log.open_topic ("noid-microphone")

local SETTING = "noid.microphone.disabled"
local ENFORCEMENT_INTERVAL_MSEC = 1000
local ENFORCEMENT_COALESCE_MSEC = 50
local pending_enforcement = {}
local mixer = Plugin.find ("mixer-api")

if not mixer then
  error ("required mixer-api is unavailable")
end

local sources = ObjectManager {
  Interest {
    type = "node",
    Constraint { "media.class", "matches", "Audio/Source*", type = "pw-global" },
  }
}

local function current_mute (node)
  local node_id = node["bound-id"]
  if not node_id then
    return nil
  end

  local volume = mixer:call ("get-volume", node_id)
  if volume and volume.mute ~= nil then
    return volume.mute
  end
  return nil
end

local function set_mute (node, desired, force, reason)
  local node_id = node["bound-id"]
  if not node_id then
    return false
  end

  local current = current_mute (node)
  if current == desired and not force then
    return true
  end

  -- Component dependencies guarantee that mixer-api is loaded before this
  -- script, but its object manager learns about a newly-bound node
  -- asynchronously. Defer until its effective route state is readable; the
  -- mixer changed signal and bounded fallback both retry the reconciliation.
  if current == nil then
    log:debug (node, string.format (
      "mixer state not readable yet; deferred mute=%s (%s)",
      tostring (desired), reason))
    return false
  end

  local success = mixer:call ("set-volume", node_id, { mute = desired })
  if success then
    log:info (node, string.format ("set mute=%s (%s)", tostring (desired), reason))
    return true
  end

  log:warning (node, string.format (
    "failed to set mute=%s through mixer-api (%s)", tostring (desired), reason))
  return false
end

local function apply_to_all (desired, force, reason)
  for node in sources:iterate () do
    set_mute (node, desired, force, reason)
  end
end

local function schedule_enforcement (node, reason)
  local node_id = node["bound-id"]
  if not node_id or pending_enforcement[node_id] then
    return
  end

  pending_enforcement[node_id] = Core.timeout_add (
    ENFORCEMENT_COALESCE_MSEC, function ()
      pending_enforcement[node_id] = nil
      if (node:get_active_features () & Feature.Proxy.BOUND) ~= 0 and
          Settings.get_boolean (SETTING) then
        set_mute (node, true, false, reason)
      end
    end)
end

sources:connect ("object-added", function (_, node)
  if Settings.get_boolean (SETTING) then
    if not set_mute (node, true, true,
        "capture source added while privacy policy is active") then
      schedule_enforcement (node,
        "capture source became mixer-ready while privacy policy is active")
    end
  end
end)

local enforce_unmute_hook = SimpleEventHook {
  name = "noid/microphone-privacy-enforce",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "node-params-changed" },
      Constraint { "media.class", "matches", "Audio/Source*" },
    },
  },
  execute = function (event)
    if Settings.get_boolean (SETTING) then
      schedule_enforcement (event:get_subject (),
        "node parameter changed while privacy policy is active")
    end
  end,
}

-- mixer-api tracks the effective device Route for ACP/UCM-backed ALSA nodes.
-- Hardware mute keys and panel controls change this state without necessarily
-- changing the node Props parameter observed by the standard event source.
mixer:connect ("changed", function (_, changed_id)
  if not Settings.get_boolean (SETTING) then
    return
  end
  for node in sources:iterate () do
    if node["bound-id"] == changed_id then
      schedule_enforcement (node,
        "mixer route changed while privacy policy is active")
      return
    end
  end
end)

Settings.subscribe (SETTING, function ()
  local disabled = Settings.get_boolean (SETTING)
  apply_to_all (disabled, true, "privacy setting changed")
end)

enforce_unmute_hook:register ()
sources:activate ()

-- Covers sources already known if component activation occurs after discovery;
-- object-added covers the normal asynchronous discovery path. Force the native
-- mixer write once so a restored software mute also reconciles the UCM route,
-- its ALSA capture control and any kernel-managed microphone-mute LED.
if Settings.get_boolean (SETTING) then
  apply_to_all (true, true, "privacy component initialized")
end

-- Event signals are authoritative. This low-frequency integrity fallback reads
-- mixer-api's effective state and writes only when a source actually drifted.
Core.timeout_add (ENFORCEMENT_INTERVAL_MSEC, function ()
  if Settings.get_boolean (SETTING) then
    apply_to_all (true, false, "periodic privacy integrity check")
  end
  return true
end)
