#include <LuaType/LuaModRef.hpp>
#include <stdexcept>

#include <Mod/LuaMod.hpp>

namespace RC::LuaType
{
    LuaModRef::LuaModRef(RC::LuaMod* object) : RemoteObjectBase<RC::LuaMod, ModName>(object)
    {
    }

    auto LuaModRef::construct(const LuaMadeSimple::Lua& lua, RC::LuaMod* cpp_object) -> const LuaMadeSimple::Lua::Table
    {
        LuaType::LuaModRef lua_object{cpp_object};

        auto metatable_name = ClassName::ToString();

        LuaMadeSimple::Lua::Table table = lua.get_metatable(metatable_name);
        if (lua.is_nil(-1))
        {
            lua.discard_value(-1);
            lua.prepare_new_table();
            setup_metamethods(lua_object);
            setup_member_functions<LuaMadeSimple::Type::IsFinal::Yes>(table);
            lua.new_metatable<LuaType::LuaModRef>(metatable_name, lua_object.get_metamethods());
        }

        // Create object & surrender ownership to Lua
        lua.transfer_stack_object(std::move(lua_object), metatable_name, lua_object.get_metamethods());

        return table;
    }

    auto LuaModRef::setup_metamethods(BaseObject& base_object) -> void
    {
        base_object.get_metamethods().create(LuaMadeSimple::Lua::MetaMethod::NewIndex, [](const LuaMadeSimple::Lua& lua) -> int {
            auto& lua_object = lua.get_userdata<LuaModRef>();
            if (!lua.is_string())
            {
                return 0;
            }
            const auto field_name = ensure_str(lua.get_string());
            if (field_name == STR("OnUnload"))
            {
                if (lua.is_function())
                {
                    lua_object.get_remote_cpp_object()->set_on_unload_callback(lua.registry().make_ref());
                }
                else if (lua.is_nil())
                {
                    lua_object.get_remote_cpp_object()->set_on_unload_callback(LUA_REFNIL);
                }
            }
            return 0;
        });
    }

    namespace
    {
        auto free_shared_lua_variable(RC::LuaMod::SharedLuaVariable& var) -> void
        {
            if (!var.value)
            {
                var.lua_type = LUA_TNIL;
                return;
            }
            switch (var.lua_type)
            {
            case LUA_TBOOLEAN:
                delete static_cast<bool*>(var.value);
                break;
            case LUA_TLIGHTUSERDATA:
            case LUA_TUSERDATA:
                delete static_cast<RC::LuaMod::SharedLuaVariable::UserdataContainer*>(var.value);
                break;
            case LUA_TNUMBER:
                if (var.is_integer)
                {
                    delete static_cast<int64_t*>(var.value);
                }
                else
                {
                    delete static_cast<double*>(var.value);
                }
                break;
            case LUA_TSTRING:
                delete static_cast<std::string*>(var.value);
                break;
            default:
                break;
            }
            var.value = nullptr;
            var.lua_type = LUA_TNIL;
        }
    }

    template <LuaMadeSimple::Type::IsFinal is_final>
    auto LuaModRef::setup_member_functions(const LuaMadeSimple::Lua::Table& table) -> void
    {
        table.add_pair("SetSharedVariable", [](const LuaMadeSimple::Lua& lua) -> int {
            std::string error_overload_not_found{R"(
No overload found for function 'SetSharedVariable'.
Overloads:
#1: SetSharedVariable(string VariableName, any Value))"};
            lua.discard_value(); // Discard the 'this' param.

            if (!lua.is_string())
            {
                throw std::runtime_error{error_overload_not_found};
            }
            auto variable_name = std::string{lua.get_string()};

            auto type = lua_type(lua.get_lua_state(), 1);
            void* new_value{};
            bool is_integer{false};

            if (type == LUA_TNIL)
            {
                new_value = nullptr;
            }
            else if (type == LUA_TBOOLEAN)
            {
                new_value = new bool{lua.get_bool()};
            }
            else if (type == LUA_TLIGHTUSERDATA)
            {
                new_value = new RC::LuaMod::SharedLuaVariable::UserdataContainer{lua_touserdata(lua.get_lua_state(), 1)};
            }
            else if (type == LUA_TNUMBER)
            {
                if (lua_isinteger(lua.get_lua_state(), 1))
                {
                    new_value = new int64_t{lua.get_integer()};
                    is_integer = true;
                }
                else
                {
                    new_value = new double{lua.get_number()};
                }
            }
            else if (type == LUA_TSTRING)
            {
                new_value = new std::string{lua.get_string()};
            }
            else if (type == LUA_TTABLE)
            {
                lua.throw_error("Tried to set shared variable but the variable is unsupported type: 'table'.");
            }
            else if (type == LUA_TFUNCTION)
            {
                lua.throw_error("Tried to set shared variable but the variable is unsupported type: 'function'.");
            }
            else if (type == LUA_TUSERDATA)
            {
                auto& userdata = lua.get_userdata<LuaType::UE4SSBaseObject>();
                std::string_view lua_object_name = userdata.get_object_name();
                if (lua_object_name == "UObject" || lua_object_name == "UWorld" || lua_object_name == "AActor" || lua_object_name == "UClass" ||
                    lua_object_name == "UEnum" || lua_object_name == "UScriptStruct" || lua_object_name == "UStruct")
                {
                    new_value = new RC::LuaMod::SharedLuaVariable::UserdataContainer{userdata.get_remote_cpp_object()};
                }
                else
                {
                    lua.throw_error("Tried to set shared variable but the variable is unsupported type: 'userdata' other than UObject derivative.");
                }
            }
            else if (type == LUA_TTHREAD)
            {
                lua.throw_error("Tried to set shared variable but the variable is unsupported type: 'thread'.");
            }

            {
                std::lock_guard<std::mutex> guard{RC::LuaMod::m_shared_lua_variables_mutex};
                if (auto it = RC::LuaMod::m_shared_lua_variables.find(variable_name); it != RC::LuaMod::m_shared_lua_variables.end())
                {
                    free_shared_lua_variable(it->second);
                }
                RC::LuaMod::m_shared_lua_variables[variable_name] = RC::LuaMod::SharedLuaVariable{type, new_value, is_integer};
            }

            return 0;
        });

        table.add_pair("GetSharedVariable", [](const LuaMadeSimple::Lua& lua) -> int {
            std::string error_overload_not_found{R"(
No overload found for function 'GetSharedVariable'.
Overloads:
#1: GetSharedVariable(string VariableName))"};
            lua.discard_value(); // Discard the 'this' param.

            if (!lua.is_string())
            {
                throw std::runtime_error{error_overload_not_found};
            }
            auto variable_name = std::string{lua.get_string()};

            std::lock_guard<std::mutex> guard{RC::LuaMod::m_shared_lua_variables_mutex};
            if (auto it = RC::LuaMod::m_shared_lua_variables.find(variable_name); it != RC::LuaMod::m_shared_lua_variables.end())
            {
                auto value = it->second.value;
                if (it->second.lua_type == LUA_TNIL)
                {
                    lua.set_nil();
                }
                else if (it->second.lua_type == LUA_TBOOLEAN)
                {
                    lua.set_bool(*static_cast<bool*>(value));
                }
                else if (it->second.lua_type == LUA_TLIGHTUSERDATA)
                {
                    lua_pushlightuserdata(lua.get_lua_state(), static_cast<RC::LuaMod::SharedLuaVariable::UserdataContainer*>(value)->userdata);
                }
                else if (it->second.lua_type == LUA_TNUMBER)
                {
                    if (it->second.is_integer)
                    {
                        lua.set_integer(*static_cast<int64_t*>(value));
                    }
                    else
                    {
                        lua.set_number(*static_cast<double*>(value));
                    }
                }
                else if (it->second.lua_type == LUA_TSTRING)
                {
                    lua.set_string(static_cast<std::string*>(value)->c_str());
                }
                else if (it->second.lua_type == LUA_TTABLE)
                {
                    lua.throw_error("Tried to get shared variable but the variable is unsupported type: 'table'.");
                }
                else if (it->second.lua_type == LUA_TFUNCTION)
                {
                    lua.throw_error("Tried to get shared variable but the variable is unsupported type: 'function'.");
                }
                else if (it->second.lua_type == LUA_TUSERDATA)
                {
                    auto_construct_object(lua, static_cast<Unreal::UObject*>(static_cast<RC::LuaMod::SharedLuaVariable::UserdataContainer*>(value)->userdata));
                }
                else if (it->second.lua_type == LUA_TTHREAD)
                {
                    lua.throw_error("Tried to get shared variable but the variable is unsupported type: 'thread'.");
                }
            }
            else
            {
                lua.set_nil();
            }

            return 1;
        });

        if constexpr (is_final == LuaMadeSimple::Type::IsFinal::Yes)
        {
            table.add_pair("type", [](const LuaMadeSimple::Lua& lua) -> int {
                lua.set_string(ClassName::ToString());
                return 1;
            });

            // If this is the final object then we also want to finalize creating the table
            // If not then it's the responsibility of the overriding object to call 'make_global()'
            // table.make_global(ClassName::ToString());
        }
    }
} // namespace RC::LuaType
