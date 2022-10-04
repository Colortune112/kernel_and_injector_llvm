/*
 * Copyright 2017 - 2021 Justas Masiulis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#ifndef JM_XORSTR_HPP
#define JM_XORSTR_HPP
#define JM_XORSTR_DISABLE_AVX_INTRINSICS

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#include <arm_neon.h>
#elif defined(_M_X64) || defined(__amd64__) || defined(_M_IX86) || defined(__i386__)
#include <immintrin.h>
#else
#error Unsupported platform
#endif

// STRUCT TEMPLATE enable_if
template <bool _Test, class _Ty = void>
struct enable_if {}; // no member "type" when !_Test

template <class _Ty>
struct enable_if<true, _Ty> { // type is _Ty for _Test
    using type = _Ty;
};

template <bool _Test, class _Ty = void>
using enable_if_t = typename enable_if<_Test, _Ty>::type;

template <class _Ty, _Ty _Val>
struct integral_constant
{
    static constexpr _Ty value = _Val;

    using value_type = _Ty;
    using type = integral_constant;

    constexpr operator value_type( ) const noexcept
    {
        return value;
    }

    constexpr value_type operator()( ) const noexcept
    {
        return value;
    }
};

template <bool _Val>
using bool_constant = integral_constant<bool, _Val>;

template <class, class>
inline constexpr bool is_same_v = false; // determine whether arguments are the same type
template <class _Ty>
inline constexpr bool is_same_v<_Ty, _Ty> = true;

template <class _Ty1, class _Ty2>
struct is_same : bool_constant<is_same_v<_Ty1, _Ty2>> { };

template <class _Ty>
struct remove_cv
{ // remove top-level const and volatile qualifiers
    using type = _Ty;

    template <template <class> class _Fn>
    using _Apply = _Fn<_Ty>; // apply cv-qualifiers from the class template argument to _Fn<_Ty>
};

template <class _Ty>
struct remove_cv<const _Ty>
{
    using type = _Ty;

    template <template <class> class _Fn>
    using _Apply = const _Fn<_Ty>;
};

template <class _Ty>
struct remove_cv<volatile _Ty>
{
    using type = _Ty;

    template <template <class> class _Fn>
    using _Apply = volatile _Fn<_Ty>;
};

template <class _Ty>
struct remove_cv<const volatile _Ty>
{
    using type = _Ty;

    template <template <class> class _Fn>
    using _Apply = const volatile _Fn<_Ty>;
};

template <class _Ty>
using remove_cv_t = typename remove_cv<_Ty>::type;

// STRUCT TEMPLATE disjunction
template <bool _First_value, class _First, class... _Rest>
struct _Disjunction
{ // handle true trait or last trait
    using type = _First;
};

template <class _False, class _Next, class... _Rest>
struct _Disjunction<false, _False, _Next, _Rest...>
{ // first trait is false, try the next trait
    using type = typename _Disjunction<_Next::value, _Next, _Rest...>::type;
};

template <class... _Traits>
struct disjunction : false_type { }; // If _Traits is empty, false_type

template <class _First, class... _Rest>
struct disjunction<_First, _Rest...> : _Disjunction<_First::value, _First, _Rest...>::type
{
    // the first true trait in _Traits, or the last trait if none are true
};

template <class... _Traits>
inline constexpr bool disjunction_v = disjunction<_Traits...>::value;

// VARIABLE TEMPLATE _Is_any_of_v
template <class _Ty, class... _Types>
inline constexpr bool _Is_any_of_v = // true if and only if _Ty is in _Types
disjunction_v<is_same<_Ty, _Types>...>;

template <class _Ty>
inline constexpr bool is_integral_v = _Is_any_of_v<remove_cv_t<_Ty>, bool, char, signed char, unsigned char,
    wchar_t,
#ifdef __cpp_char8_t
    char8_t,
#endif // __cpp_char8_t
    char16_t, char32_t, short, unsigned short, int, unsigned int, long, unsigned long, long long, unsigned long long>;

template <class _Ty>
struct remove_reference
{
    using type = _Ty;
    using _Const_thru_ref_type = const _Ty;
};

template <class _Ty>
struct remove_reference<_Ty&>
{
    using type = _Ty;
    using _Const_thru_ref_type = const _Ty&;
};

template <class _Ty>
struct remove_reference<_Ty&&>
{
    using type = _Ty;
    using _Const_thru_ref_type = const _Ty&&;
};

template <class _Ty>
using remove_reference_t = typename remove_reference<_Ty>::type;

template <class _Ty>
struct remove_const
{ // remove top-level const qualifier
    using type = _Ty;
};

template <class _Ty>
struct remove_const<const _Ty>
{
    using type = _Ty;
};

template <class _Ty>
using remove_const_t = typename remove_const<_Ty>::type;

template <class _Ty, _Ty... _Vals>
struct integer_sequence
{ // sequence of integer parameters
    static_assert( is_integral_v<_Ty>, "integer_sequence<T, I...> requires T to be an integral type." );

    using value_type = _Ty;

    static constexpr size_t size( ) noexcept
    {
        return sizeof...( _Vals );
    }
};

// ALIAS TEMPLATE make_integer_sequence
template <class _Ty, _Ty _Size>
using make_integer_sequence = __make_integer_seq<integer_sequence, _Ty, _Size>;

template <size_t... _Vals>
using index_sequence = integer_sequence<size_t, _Vals...>;

template <size_t _Size>
using make_index_sequence = make_integer_sequence<size_t, _Size>;

template <size_t>
struct _Make_unsigned2; // Choose make_unsigned strategy by type size

template <>
struct _Make_unsigned2<1>
{
    template <class>
    using _Apply = unsigned char;
};

template <>
struct _Make_unsigned2<2>
{
    template <class>
    using _Apply = unsigned short;
};

template <bool>
struct _Select
{ // Select between aliases that extract either their first or second parameter
    template <class _Ty1, class>
    using _Apply = _Ty1;
};

template <>
struct _Select<false>
{
    template <class, class _Ty2>
    using _Apply = _Ty2;
};

template <>
struct _Make_unsigned2<4>
{
    template <class _Ty>
    using _Apply = // assumes LLP64
        typename _Select<is_same_v<_Ty, long> || is_same_v<_Ty, unsigned long>>::template _Apply<unsigned long,
        unsigned int>;
};

template <>
struct _Make_unsigned2<8>
{
    template <class>
    using _Apply = unsigned long long;
};

template <class _Ty>
using _Make_unsigned1 = // unsigned partner to cv-unqualified _Ty
typename _Make_unsigned2<sizeof( _Ty )>::template _Apply<_Ty>;

template <class _Ty>
inline constexpr bool _Is_nonbool_integral = is_integral_v<_Ty> && !is_same_v<remove_cv_t<_Ty>, bool>;

template <class _Ty>
struct is_enum : bool_constant<__is_enum( _Ty )> { }; // determine whether _Ty is an enumerated type

template <class _Ty>
inline constexpr bool is_enum_v = __is_enum( _Ty );

template <class _Ty>
struct make_unsigned
{ // unsigned partner to _Ty
    static_assert( _Is_nonbool_integral<_Ty> || is_enum_v<_Ty>,
                   "make_unsigned<T> requires that T shall be a (possibly cv-qualified) "
                   "integral type or enumeration but not a bool type." );

    using type = typename remove_cv<_Ty>::template _Apply<_Make_unsigned1>;
};

#define xorstr(str) ::jm::xor_string([]() { return str; }, ::integral_constant<size_t, sizeof(str) / sizeof(*str)>{}, make_index_sequence<::jm::detail::_buffer_size<sizeof(str)>()>{})
//#define _(str) ( str )
#define _(str) xorstr(str).crypt_get()

#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline)) inline
#endif

#if defined(__clang__) || defined(__GNUC__)
#define JM_XORSTR_LOAD_FROM_REG(x) ::jm::detail::load_from_reg(x)
#else
#define JM_XORSTR_LOAD_FROM_REG(x) (x)
#endif

namespace jm
{

    namespace detail
    {

        template<size_t Size>
        XORSTR_FORCEINLINE constexpr size_t _buffer_size( )
        {
            return ( ( Size / 16 ) + ( Size % 16 != 0 ) ) * 2;
        }

        template<uint32_t Seed>
        XORSTR_FORCEINLINE constexpr uint32_t key4( ) noexcept
        {
            uint32_t value = Seed;
            for ( char c : __TIME__ )
                value = static_cast< uint32_t >( ( value ^ c ) * 16777619ull );
            return value;
        }

        template<size_t S>
        XORSTR_FORCEINLINE constexpr uint64_t key8( )
        {
            constexpr auto first_part = key4<2166136261 + S>( );
            constexpr auto second_part = key4<first_part>( );
            return ( static_cast< uint64_t >( first_part ) << 32 ) | second_part;
        }

        // loads up to 8 characters of string into uint64 and xors it with the key
        template<size_t N, class CharT>
        XORSTR_FORCEINLINE constexpr uint64_t
            load_xored_str8( uint64_t key, size_t idx, const CharT* str ) noexcept
        {
            using cast_type = typename make_unsigned<CharT>::type;
            constexpr auto value_size = sizeof( CharT );
            constexpr auto idx_offset = 8 / value_size;

            uint64_t value = key;
            for ( size_t i = 0; i < idx_offset && i + idx * idx_offset < N; ++i )
                value ^=
                ( uint64_t{ static_cast< cast_type >( str[ i + idx * idx_offset ] ) }
            << ( ( i % idx_offset ) * 8 * value_size ) );

            return value;
        }

        // forces compiler to use registers instead of stuffing constants in rdata
        XORSTR_FORCEINLINE uint64_t load_from_reg( uint64_t value ) noexcept
        {
#if defined(__clang__) || defined(__GNUC__)
            asm( "" : "=r"( value ) : "0"( value ) : );
#endif
            return value;
        }

        template<uint64_t V>
        struct uint64_v
        {
            constexpr static uint64_t value = V;
        };

    } // namespace detail

    template<class CharT, size_t Size, class Keys, class Indices>
    class xor_string;

    template<class CharT, size_t Size, uint64_t... Keys, size_t... Indices>
    class xor_string<CharT, Size, integer_sequence<uint64_t, Keys...>, index_sequence<Indices...>>
    {
#ifndef JM_XORSTR_DISABLE_AVX_INTRINSICS
        constexpr static inline uint64_t alignment = ( ( Size > 16 ) ? 32 : 16 );
#else
        constexpr static inline uint64_t alignment = 16;
#endif

        alignas( alignment ) uint64_t _storage[ sizeof...( Keys ) ];

    public:
        using value_type = CharT;
        using size_type = size_t;
        using pointer = CharT*;
        using const_pointer = const CharT*;

        template<class L>
        XORSTR_FORCEINLINE xor_string( L l, ::integral_constant<size_t, Size>, index_sequence<Indices...> ) noexcept
            : _storage{ JM_XORSTR_LOAD_FROM_REG( detail::uint64_v<detail::load_xored_str8<Size>( Keys, Indices, l( ) )>::value )... }
        {
        }

        XORSTR_FORCEINLINE constexpr size_type size( ) const noexcept
        {
            return Size - 1;
        }

        XORSTR_FORCEINLINE void crypt( ) noexcept
        {
            // everything is inlined by hand because a certain compiler with a certain linker is _very_ slow
#if defined(__clang__)
            alignas( alignment )
                uint64_t arr[ ]{ JM_XORSTR_LOAD_FROM_REG( Keys )... };
            uint64_t* keys =
                ( uint64_t* )JM_XORSTR_LOAD_FROM_REG( ( uint64_t )arr );
#else
            alignas( alignment ) uint64_t keys[ ]{ JM_XORSTR_LOAD_FROM_REG( Keys )... };
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#if defined(__clang__)
            ( ( Indices >= sizeof( _storage ) / 16 ? static_cast< void >( 0 ) : __builtin_neon_vst1q_v(
                reinterpret_cast< uint64_t* >( _storage ) + Indices * 2,
                veorq_u64( __builtin_neon_vld1q_v( reinterpret_cast< const uint64_t* >( _storage ) + Indices * 2, 51 ),
                __builtin_neon_vld1q_v( reinterpret_cast< const uint64_t* >( keys ) + Indices * 2, 51 ) ),
                51 ) ), ... );
#else // GCC, MSVC
            ( ( Indices >= sizeof( _storage ) / 16 ? static_cast< void >( 0 ) : vst1q_u64(
                reinterpret_cast< uint64_t* >( _storage ) + Indices * 2,
                veorq_u64( vld1q_u64( reinterpret_cast< const uint64_t* >( _storage ) + Indices * 2 ),
                vld1q_u64( reinterpret_cast< const uint64_t* >( keys ) + Indices * 2 ) ) ) ), ... );
#endif
#elif !defined(JM_XORSTR_DISABLE_AVX_INTRINSICS)
            ( ( Indices >= sizeof( _storage ) / 32 ? static_cast< void >( 0 ) : _mm256_store_si256(
                reinterpret_cast< __m256i* >( _storage ) + Indices,
                _mm256_xor_si256(
                _mm256_load_si256( reinterpret_cast< const __m256i* >( _storage ) + Indices ),
                _mm256_load_si256( reinterpret_cast< const __m256i* >( keys ) + Indices ) ) ) ), ... );

            if constexpr ( sizeof( _storage ) % 32 != 0 )
                _mm_store_si128(
                    reinterpret_cast< __m128i* >( _storage + sizeof...( Keys ) - 2 ),
                    _mm_xor_si128( _mm_load_si128( reinterpret_cast< const __m128i* >( _storage + sizeof...( Keys ) - 2 ) ),
                    _mm_load_si128( reinterpret_cast< const __m128i* >( keys + sizeof...( Keys ) - 2 ) ) ) );
#else
            ( ( Indices >= sizeof( _storage ) / 16 ? static_cast< void >( 0 ) : _mm_store_si128(
                reinterpret_cast< __m128i* >( _storage ) + Indices,
                _mm_xor_si128( _mm_load_si128( reinterpret_cast< const __m128i* >( _storage ) + Indices ),
                _mm_load_si128( reinterpret_cast< const __m128i* >( keys ) + Indices ) ) ) ), ... );
#endif
        }

        XORSTR_FORCEINLINE const_pointer get( ) const noexcept
        {
            return reinterpret_cast< const_pointer >( _storage );
        }

        XORSTR_FORCEINLINE pointer get( ) noexcept
        {
            return reinterpret_cast< pointer >( _storage );
        }

        XORSTR_FORCEINLINE pointer crypt_get( ) noexcept
        {
            // crypt() is inlined by hand because a certain compiler with a certain linker is _very_ slow
#if defined(__clang__)
            alignas( alignment )
                uint64_t arr[ ]{ JM_XORSTR_LOAD_FROM_REG( Keys )... };
            uint64_t* keys =
                ( uint64_t* )JM_XORSTR_LOAD_FROM_REG( ( uint64_t )arr );
#else
            alignas( alignment ) uint64_t keys[ ]{ JM_XORSTR_LOAD_FROM_REG( Keys )... };
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#if defined(__clang__)
            ( ( Indices >= sizeof( _storage ) / 16 ? static_cast< void >( 0 ) : __builtin_neon_vst1q_v(
                reinterpret_cast< uint64_t* >( _storage ) + Indices * 2,
                veorq_u64( __builtin_neon_vld1q_v( reinterpret_cast< const uint64_t* >( _storage ) + Indices * 2, 51 ),
                __builtin_neon_vld1q_v( reinterpret_cast< const uint64_t* >( keys ) + Indices * 2, 51 ) ),
                51 ) ), ... );
#else // GCC, MSVC
            ( ( Indices >= sizeof( _storage ) / 16 ? static_cast< void >( 0 ) : vst1q_u64(
                reinterpret_cast< uint64_t* >( _storage ) + Indices * 2,
                veorq_u64( vld1q_u64( reinterpret_cast< const uint64_t* >( _storage ) + Indices * 2 ),
                vld1q_u64( reinterpret_cast< const uint64_t* >( keys ) + Indices * 2 ) ) ) ), ... );
#endif
#elif !defined(JM_XORSTR_DISABLE_AVX_INTRINSICS)
            ( ( Indices >= sizeof( _storage ) / 32 ? static_cast< void >( 0 ) : _mm256_store_si256(
                reinterpret_cast< __m256i* >( _storage ) + Indices,
                _mm256_xor_si256(
                _mm256_load_si256( reinterpret_cast< const __m256i* >( _storage ) + Indices ),
                _mm256_load_si256( reinterpret_cast< const __m256i* >( keys ) + Indices ) ) ) ), ... );

            if constexpr ( sizeof( _storage ) % 32 != 0 )
                _mm_store_si128(
                    reinterpret_cast< __m128i* >( _storage + sizeof...( Keys ) - 2 ),
                    _mm_xor_si128( _mm_load_si128( reinterpret_cast< const __m128i* >( _storage + sizeof...( Keys ) - 2 ) ),
                    _mm_load_si128( reinterpret_cast< const __m128i* >( keys + sizeof...( Keys ) - 2 ) ) ) );
#else
            ( ( Indices >= sizeof( _storage ) / 16 ? static_cast< void >( 0 ) : _mm_store_si128(
                reinterpret_cast< __m128i* >( _storage ) + Indices,
                _mm_xor_si128( _mm_load_si128( reinterpret_cast< const __m128i* >( _storage ) + Indices ),
                _mm_load_si128( reinterpret_cast< const __m128i* >( keys ) + Indices ) ) ) ), ... );
#endif

            return ( pointer )( _storage );
        }
    };

    template<class L, size_t Size, size_t... Indices>
    xor_string( L l, ::integral_constant<size_t, Size>, index_sequence<Indices...> )->xor_string<
        ::remove_const_t<::remove_reference_t<decltype( l( )[ 0 ] )>>,
        Size,
        integer_sequence<uint64_t, detail::key8<Indices>( )...>,
        index_sequence<Indices...>>;

} // namespace jm

#endif // include guard