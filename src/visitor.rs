use serde::{de, Deserialize};
use std::{borrow::Cow, collections::HashSet, fmt::Formatter, marker::PhantomData, str::FromStr};

use crate::stmt::LogFlag;

type CowCowStrs<'a> = Cow<'a, [Cow<'a, str>]>;

/// Deserialize null, a string, or string sequence into an `Option<Cow<'a, [Cow<'a, str>]>>`.
pub fn single_string_to_option_vec<'a, 'de, D>(
    deserializer: D,
) -> Result<Option<CowCowStrs<'a>>, D::Error>
where
    D: de::Deserializer<'de>,
{
    match single_string_to_vec::<'a, 'de, D>(deserializer) {
        Ok(value) => match value.len() {
            0 => Ok(None),
            _ => Ok(Some(value)),
        },
        Err(err) => Err(err),
    }
}

/// Deserialize null, a string or string sequence into a `Cow<'a, [Cow<'a, str>]>`.
pub fn single_string_to_vec<'a, 'de, D>(deserializer: D) -> Result<CowCowStrs<'a>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct StringOrVec<'a>(PhantomData<CowCowStrs<'a>>);
    impl<'a, 'de> de::Visitor<'de> for StringOrVec<'a> {
        type Value = CowCowStrs<'a>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("single string or list of strings")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok([][..].into())
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Cow::Owned(vec![Cow::Owned(value.to_owned())]))
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }

    deserializer.deserialize_any(StringOrVec(PhantomData))
}

/// Deserialize null, a string or string sequence into an `Option<HashSet<LogFlag>>`.
pub fn single_string_to_option_hashset_logflag<'de, D>(
    deserializer: D,
) -> Result<Option<HashSet<LogFlag>>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct LogFlagSet(PhantomData<Option<HashSet<LogFlag>>>);
    impl<'de> de::Visitor<'de> for LogFlagSet {
        type Value = Option<HashSet<LogFlag>>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("single string or list of strings")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let mut h: HashSet<LogFlag> = HashSet::new();
            h.insert(LogFlag::from_str(value).map_err(<E>::custom)?);
            Ok(Some(h))
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            let h: HashSet<LogFlag> =
                Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))?;
            Ok(Some(h))
        }
    }
    deserializer.deserialize_any(LogFlagSet(PhantomData))
}

/// Serialize an [Option] with [Option::None] value as `0`.
pub fn serialize_none_to_zero<S, T>(x: &Option<T>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: serde::Serialize,
{
    match x {
        Some(v) => s.serialize_some(v),
        None => s.serialize_some(&0_usize),
    }
}

/// Deserialize string or array of strings into the given HashSet type.
pub fn deserialize_flags<'de, D, T>(deserializer: D) -> Result<HashSet<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: FromStr + Eq + core::hash::Hash + Deserialize<'de>,
    <T as FromStr>::Err: std::fmt::Display,
{
    struct FlagSet<T>(PhantomData<T>);
    impl<'de, T> de::Visitor<'de> for FlagSet<T>
    where
        T: FromStr + Eq + core::hash::Hash + Deserialize<'de>,
        <T as FromStr>::Err: std::fmt::Display,
    {
        type Value = HashSet<T>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("single string or list of strings")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(HashSet::default())
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
            <T as FromStr>::Err: std::fmt::Display,
        {
            let mut h: HashSet<T> = HashSet::new();
            h.insert(T::from_str(value).map_err(<E>::custom)?);
            Ok(h)
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }
    deserializer.deserialize_any(FlagSet(PhantomData))
}
